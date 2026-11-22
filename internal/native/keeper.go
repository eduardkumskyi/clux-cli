package native

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// The slot keeper is the root half of slot reuse. A slot's supervisor runs
// as the slot user -- the same uid as the agent it supervises -- so the
// agent can stop it, kill it, or leave things behind that the supervisor
// never sees (a crontab, launchd user-domain jobs, files in shared temp
// dirs). Before a slot goes to another workspace, root therefore removes
// everything the uid left (keeper_darwin.go) and records that in a
// root-owned state file; the owner's host agent hands out only slots that
// root reports clean, and a supervisor refuses to start a workspace root
// has not recorded as holding the slot.
//
// Protocol: one JSON request line, one JSON response line per connection on
// KeeperSocket (root:_cluxctl 0660, in root-owned RunDir). The keeper serves
// only the configured owner (and root); its clients check that the socket
// was bound by root (listen-time peer credentials), see VerifyRootListener.

// Keeper ops.
const (
	KeeperOpState = "state"
	KeeperOpClaim = "claim"
	KeeperOpWipe  = "wipe"
)

// SlotState is the keeper's record of one slot.
type SlotState struct {
	Slot int `json:"slot"`
	// Known: root has a record of this slot (false for a slot nobody used
	// since the keeper exists, e.g. right after an upgrade).
	Known bool `json:"known"`
	// ClaimedBy is the workspace that holds the slot ("" = none).
	ClaimedBy string `json:"claimed_by,omitempty"`
	// Clean: root wiped the slot and nobody claimed it since.
	Clean bool `json:"clean"`
	// Busy: a wipe is running.
	Busy      bool   `json:"busy,omitempty"`
	Updated   string `json:"updated,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// Free reports whether the slot may go to a new workspace as it is.
func (s SlotState) Free() bool { return s.Known && s.Clean && s.ClaimedBy == "" && !s.Busy }

// KeeperRequest is one keeper call.
type KeeperRequest struct {
	Op          string `json:"op"`
	Slot        int    `json:"slot"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	// Version / AllowDowngrade: KeeperOpUpdate's target release tag, and
	// whether it may be older than the installed one.
	Version        string `json:"version,omitempty"`
	AllowDowngrade bool   `json:"allow_downgrade,omitempty"`
}

// KeeperResponse is the reply to a KeeperRequest.
type KeeperResponse struct {
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
	State      *SlotState    `json:"state,omitempty"`
	FreedBytes int64         `json:"freed_bytes,omitempty"`
	Update     *UpdateResult `json:"update,omitempty"`
	// Version: KeeperOpVersion's answer.
	Version string `json:"version,omitempty"`
}

// claimSlot is the claim rule: a workspace may take a slot that is free,
// that it already holds, or -- for a slot root has no record of (an
// installation from before the keeper) -- whose only resident workspace is
// that workspace itself. Anything else needs a wipe first.
func claimSlot(st SlotState, id string, resident []string) (SlotState, error) {
	switch {
	case st.Busy:
		return st, fmt.Errorf("slot %d is being wiped", st.Slot)
	case st.ClaimedBy == id:
		return st, nil
	case st.ClaimedBy != "":
		return st, fmt.Errorf("slot %d is held by workspace %s", st.Slot, st.ClaimedBy)
	case !st.Known:
		if len(resident) != 1 || resident[0] != id {
			return st, fmt.Errorf("slot %d has not been wiped by root since an earlier workspace; it needs a wipe first", st.Slot)
		}
	case !st.Clean:
		return st, fmt.Errorf("slot %d has not been wiped by root since its last workspace; it needs a wipe first", st.Slot)
	}
	st.Known, st.ClaimedBy, st.Clean, st.LastError = true, id, false, ""
	return st, nil
}

// wipeAllowed: a wipe for workspace id may run on a slot it holds or on a
// slot nobody holds (id "" = wipe a slot no workspace holds).
func wipeAllowed(st SlotState, id string) error {
	switch {
	case st.Busy:
		return fmt.Errorf("slot %d is already being wiped", st.Slot)
	case st.ClaimedBy != "" && st.ClaimedBy != id:
		return fmt.Errorf("slot %d is held by workspace %s, not %q", st.Slot, st.ClaimedBy, id)
	}
	return nil
}

// validKeeperID mirrors egress.ValidWorkspaceID (ids end up in file names).
func validKeeperID(id string) bool {
	if len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// KeeperClient is the owner's client of the slot keeper.
type KeeperClient struct {
	Socket string
	// SkipRootCheck disables VerifyRootListener (tests only).
	SkipRootCheck bool
}

// State returns slot n's record.
func (k *KeeperClient) State(ctx context.Context, n int) (SlotState, error) {
	r, err := k.call(ctx, KeeperRequest{Op: KeeperOpState, Slot: n})
	if err != nil || r.State == nil {
		if err == nil {
			err = errors.New("slot keeper: no state in reply")
		}
		return SlotState{}, err
	}
	return *r.State, nil
}

// Claim records workspace id as slot n's holder.
func (k *KeeperClient) Claim(ctx context.Context, n int, id string) error {
	_, err := k.call(ctx, KeeperRequest{Op: KeeperOpClaim, Slot: n, WorkspaceID: id})
	return err
}

// Wipe has root clear slot n (held by id, or by nobody if id is "") and
// returns the bytes its home held.
func (k *KeeperClient) Wipe(ctx context.Context, n int, id string) (int64, error) {
	r, err := k.call(ctx, KeeperRequest{Op: KeeperOpWipe, Slot: n, WorkspaceID: id})
	return r.FreedBytes, err
}

func (k *KeeperClient) call(ctx context.Context, req KeeperRequest) (KeeperResponse, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", k.Socket)
	if err != nil {
		return KeeperResponse{}, fmt.Errorf("slot keeper not reachable (%w); is native mode installed (`sudo clux native install`)?", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if !k.SkipRootCheck {
		if err := VerifyRootListener(conn, k.Socket); err != nil {
			return KeeperResponse{}, fmt.Errorf("slot keeper: %w", err)
		}
	}
	b, _ := json.Marshal(req)
	// The keeper may refuse (wrong uid) and close before reading the
	// request; its one-line reply is still in the socket, so a failed
	// write falls through to the read and reports that reply instead.
	_, werr := conn.Write(append(b, '\n'))
	var resp KeeperResponse
	line, err := bufio.NewReaderSize(conn, 4096).ReadSlice('\n')
	if err != nil {
		if ctx.Err() != nil {
			return resp, ctx.Err()
		}
		if werr != nil {
			err = werr
		}
		return resp, fmt.Errorf("slot keeper: %w", err)
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return resp, fmt.Errorf("slot keeper: %w", err)
	}
	if !resp.OK {
		msg := resp.Error
		if msg == "" {
			msg = "request failed"
		}
		return resp, errors.New(msg)
	}
	return resp, nil
}
