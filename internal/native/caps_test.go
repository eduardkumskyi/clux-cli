package native

import (
	"context"
	"errors"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestParseXcodeAndRuntimes(t *testing.T) {
	if v := ParseXcodeVersion("Xcode 16.4\nBuild version 16F6\n"); v != "16.4" {
		t.Fatalf("got %q", v)
	}
	if v := ParseXcodeVersion("xcode-select: error: tool 'xcodebuild' requires Xcode"); v != "" {
		t.Fatalf("got %q", v)
	}
	j := []byte(`{"runtimes":[{"name":"iOS 18.6","isAvailable":true},{"name":"watchOS 11.5","isAvailable":false},{"name":"iOS 17.5","isAvailable":true}]}`)
	if got := ParseSimRuntimes(j); !reflect.DeepEqual(got, []string{"iOS 17.5", "iOS 18.6"}) {
		t.Fatalf("got %v", got)
	}
	if got := ParseSimRuntimes([]byte("nope")); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestParseToken(t *testing.T) {
	out := "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 10657851713038665265\n"
	if tok := parseToken(out); tok != "10657851713038665265" {
		t.Fatalf("got %q", tok)
	}
	if parseToken("pf already enabled") != "" {
		t.Fatal("token from nothing")
	}
}

func TestParseDSAttr(t *testing.T) {
	for in, want := range map[string]string{
		"UniqueID: 401":                       "401",
		"dsAttrTypeNative:IsHidden: 1":        "1",
		"NFSHomeDirectory: /private/var/clux": "/private/var/clux",
		"RealName:\n Clux agent":              "Clux agent",
	} {
		if got, ok := parseDSAttr(in); !ok || got != want {
			t.Errorf("parseDSAttr(%q) = %q, want %q", in, got, want)
		}
	}
	if _, ok := parseDSAttr("garbage"); ok {
		t.Error("line without a colon parsed")
	}
}

func TestPFStatusActive(t *testing.T) {
	now := time.Now()
	st := PFStatus{Enabled: true, RulesLoaded: true, MainAnchor: true, UIDs: []int{431},
		Updated: now.Add(-5 * time.Second).UTC().Format(time.RFC3339)}
	if !st.Active(now) {
		t.Fatal("fresh status inactive")
	}
	if !st.Covers(431) || st.Covers(432) {
		t.Fatal("Covers")
	}
	st.MainAnchor = false
	if st.Active(now) {
		t.Fatal("anchor not evaluated by the main ruleset, but reported active")
	}
	st.MainAnchor = true
	if st.Active(now.Add(time.Minute)) {
		t.Fatal("stale status (daemon dead) reported active")
	}
	st.Enabled = false
	if st.Active(now) {
		t.Fatal("disabled pf reported active")
	}
}

func TestCapabilities(t *testing.T) {
	if runtime.GOOS != "darwin" {
		c := &Capabilities{}
		if got := c.Collect(context.Background()); !reflect.DeepEqual(got["runtimes"], []string{"docker"}) {
			t.Fatalf("got %v", got)
		}
		return
	}
	now := time.Now()
	probes := 0
	c := &Capabilities{
		Supervisor: func(context.Context) (string, string, error) { return "0.4.0", "active", nil },
		loadConfig: func() (*Config, error) {
			return &Config{CLIVersion: "v0.5.2", Slots: []Slot{{N: 1, User: "_clux1"}, {N: 2, User: "_clux2"}, {N: 3, User: "_clux3"}}}, nil
		},
		FreeSlots: func() int { return 1 },
		pfStatus: func() (PFStatus, error) {
			return PFStatus{Enabled: true, RulesLoaded: true, MainAnchor: true, Updated: now.UTC().Format(time.RFC3339)}, nil
		},
		xcodeProbe: func(context.Context) (string, []string) { probes++; return "16.4", []string{"iOS 18.6"} },
		now:        func() time.Time { return now },
	}
	got := c.Collect(context.Background())
	want := map[string]any{
		"runtimes": []string{"docker", "native_macos"},
		"native_macos": map[string]any{
			"installed": true, "agent_user": "_clux1.._clux3", "xcode_version": "16.4",
			"simulator_runtimes": []string{"iOS 18.6"}, "sandbox": "active", "pf": "active",
			"supervisor_version": "0.4.0", "daemon_version": "v0.5.2", "slots_total": 3, "slots_free": 1,
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %#v\nwant %#v", got, want)
	}
	c.Collect(context.Background())
	if probes != 1 {
		t.Fatalf("xcode probed %d times; must be cached", probes)
	}

	// Supervisor down: still "installed" (so the UI can say what's wrong),
	// but not offered as a runtime.
	c.Supervisor = func(context.Context) (string, string, error) { return "", "", errors.New("down") }
	got = c.Collect(context.Background())
	if !reflect.DeepEqual(got["runtimes"], []string{"docker"}) || got["native_macos"].(map[string]any)["sandbox"] != "unavailable" {
		t.Fatalf("got %#v", got)
	}

	c.loadConfig = func() (*Config, error) { return nil, os.ErrNotExist }
	if got := c.Collect(context.Background()); got["native_macos"] != nil {
		t.Fatalf("not installed but got %#v", got)
	}
}
