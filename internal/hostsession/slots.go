package hostsession

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// SlotMap is the owner side's workspace -> native slot assignment
// (~/.clux/native-slots.json). A workspace keeps its slot from its first
// start until it is deleted, because its files live in that slot user's
// home and nothing else may read them; a slot therefore holds at most one
// workspace and the pool size bounds how many native workspaces exist.
type SlotMap struct {
	path  string
	total int

	mu sync.Mutex
	m  map[string]int
}

// LoadSlotMap reads the assignments (a missing file is an empty map).
// total is the number of installed slots.
func LoadSlotMap(path string, total int) (*SlotMap, error) {
	s := &SlotMap{path: path, total: total, m: map[string]int{}}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(b) > 0 {
		var f struct {
			Workspaces map[string]int `json:"workspaces"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for id, n := range f.Workspaces {
			if n >= 1 {
				s.m[id] = n
			}
		}
	}
	return s, nil
}

// Total is the number of installed slots.
func (s *SlotMap) Total() int { return s.total }

// Free counts the installed slots no workspace holds.
func (s *SlotMap) Free() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total - len(s.usedLocked())
}

// Lookup returns the slot workspace id holds.
func (s *SlotMap) Lookup(id string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.m[id]
	return n, ok
}

// Assign returns id's slot, assigning the lowest free one on first use.
// usable vets a candidate (the slot's supervisor answers and holds no other
// workspace's files); slots it rejects are skipped.
func (s *SlotMap) Assign(id string, usable func(slot int) bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.m[id]; ok {
		return n, nil
	}
	used := s.usedLocked()
	for n := 1; n <= s.total; n++ {
		if used[n] || (usable != nil && !usable(n)) {
			continue
		}
		s.m[id] = n
		if err := s.saveLocked(); err != nil {
			delete(s.m, id)
			return 0, err
		}
		return n, nil
	}
	return 0, fmt.Errorf("all %d native slots in use; run `sudo clux native install --slots %d` to add more, or delete a native workspace", s.total, s.total+1)
}

// Release frees id's slot (after the slot was wiped).
func (s *SlotMap) Release(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return nil
	}
	delete(s.m, id)
	return s.saveLocked()
}

func (s *SlotMap) usedLocked() map[int]bool {
	used := map[int]bool{}
	for _, n := range s.m {
		if n <= s.total {
			used[n] = true
		}
	}
	return used
}

func (s *SlotMap) saveLocked() error {
	if s.path == "" {
		return nil
	}
	ids := make([]string, 0, len(s.m))
	for id := range s.m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	b, err := json.MarshalIndent(struct {
		Workspaces map[string]int `json:"workspaces"`
	}{s.m}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	rnd := make([]byte, 6)
	_, _ = rand.Read(rnd)
	tmp := filepath.Join(filepath.Dir(s.path), "."+filepath.Base(s.path)+"."+hex.EncodeToString(rnd)+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
