//go:build darwin

package native

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakePF models the bits of pf the daemon talks to.
type fakePF struct {
	anchor     string // rules loaded into com.apple/clux
	mainAnchor bool
	failLoad   bool
	calls      []string
}

func (f *fakePF) run(stdin string, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	switch cmd {
	case "-a " + PFAnchor + " -f -":
		if f.failLoad {
			return "", errors.New("load failed")
		}
		f.anchor = stdin
		return "", nil
	case "-a " + PFAnchor + " -s rules":
		var shown []string
		for _, l := range strings.Split(f.anchor, "\n") {
			if l != "" && !strings.HasPrefix(l, "#") {
				shown = append(shown, l)
			}
		}
		return strings.Join(shown, "\n"), nil
	case "-s rules":
		if f.mainAnchor {
			return "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", nil
		}
		return "", nil
	case "-f /etc/pf.conf":
		f.mainAnchor = true
		return "", nil
	case "-s info":
		return "Status: Enabled for 0 days", nil
	}
	return "", nil
}

func newTestPFD(f *fakePF) (*pfd, *[]PFStatus) {
	var published []PFStatus
	d := &pfd{
		cfg: &Config{ProxyPort: 47821}, uids: []int{431, 432}, pf: f.run,
		logf:            func(string, ...any) {},
		writeStatusFile: func(st PFStatus) { published = append(published, st) },
	}
	return d, &published
}

func TestPFDReloadsAFlushedAnchor(t *testing.T) {
	f := &fakePF{mainAnchor: true}
	d, published := newTestPFD(f)
	rules := PFRules(d.uids, 501, 47821, nil)
	d.verifyMain()
	d.load(rules, true)
	if !d.loaded || f.anchor != rules {
		t.Fatal("initial load")
	}
	// Unchanged rules: no reload.
	n := len(f.calls)
	d.load(rules, false)
	if len(f.calls) != n {
		t.Fatal("reloaded unchanged rules")
	}
	// Something flushes the anchor (pfctl -a com.apple/clux -F all).
	f.anchor = ""
	d.verify()
	if f.anchor != rules || !d.loaded {
		t.Fatalf("flushed anchor not restored (loaded=%v)", d.loaded)
	}
	// Something replaces it with other rules.
	f.anchor = "pass out quick all\n"
	d.verify()
	if f.anchor != rules {
		t.Fatal("replaced anchor not restored")
	}
	d.writeStatus()
	st := (*published)[len(*published)-1]
	if !st.RulesLoaded || !st.MainAnchor || !st.Covers(431) || !st.Covers(432) {
		t.Fatalf("status %+v", st)
	}
}

func TestPFDRestoresMainRulesetAnchorPoint(t *testing.T) {
	f := &fakePF{mainAnchor: false}
	d, _ := newTestPFD(f)
	d.load(PFRules(d.uids, 501, 47821, nil), true)
	d.verify()
	if !f.mainAnchor || !d.mainAnchor {
		t.Fatal("/etc/pf.conf not reloaded when the main ruleset lacked com.apple/*")
	}
	if !d.loaded {
		t.Fatal("anchor not reloaded after restoring the main ruleset")
	}
}

func TestPFDStatusNotLoadedWhileRepairFails(t *testing.T) {
	f := &fakePF{mainAnchor: true}
	d, published := newTestPFD(f)
	d.verifyMain()
	d.load(PFRules(d.uids, 501, 47821, nil), true)
	f.anchor = ""
	f.failLoad = true
	d.verify()
	d.writeStatus()
	st := (*published)[len(*published)-1]
	if st.RulesLoaded || st.Error == "" {
		t.Fatalf("status claims loaded rules while pf holds none: %+v", st)
	}
	d.enabled = true
	if d.status().Active(time.Now()) {
		t.Fatal("inactive pf reported active")
	}
}
