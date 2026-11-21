package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type offerFake struct {
	installCalls, saveCalls, healthCalls int
	installErr, healthErr                error
	logs                                 []string
	out                                  bytes.Buffer
}

// newFakeOffer: darwin, interactive, not installed, Xcode present.
func newFakeOffer(f *offerFake, answer string) *nativeOffer {
	return &nativeOffer{
		goos:        "darwin",
		interactive: true,
		installed:   func() bool { return false },
		xcodeOK:     func() bool { return true },
		health:      func() error { f.healthCalls++; return f.healthErr },
		install:     func() error { f.installCalls++; return f.installErr },
		saveDecline: func() error { f.saveCalls++; return nil },
		in:          strings.NewReader(answer),
		out:         &f.out,
		logf:        func(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) },
	}
}

func TestNativeOfferDecide(t *testing.T) {
	cases := []struct {
		name string
		mod  func(o *nativeOffer)
		want nativeOfferAction
	}{
		{"interactive, not installed", func(o *nativeOffer) {}, offerPrompt},
		{"non-darwin", func(o *nativeOffer) { o.goos = "linux" }, offerNothing},
		{"installed", func(o *nativeOffer) { o.installed = func() bool { return true } }, offerCheckHealth},
		{"installed, non-interactive", func(o *nativeOffer) {
			o.installed = func() bool { return true }
			o.interactive = false
		}, offerCheckHealth},
		{"non-interactive", func(o *nativeOffer) { o.interactive = false }, offerHint},
		{"declined", func(o *nativeOffer) { o.declined = true }, offerNothing},
		{"flag", func(o *nativeOffer) { o.noPrompt = true }, offerNothing},
		{"flag, non-interactive", func(o *nativeOffer) { o.noPrompt = true; o.interactive = false }, offerNothing},
		{"xcode missing", func(o *nativeOffer) { o.xcodeOK = func() bool { return false } }, offerNeedsXcode},
		{"xcode missing, non-interactive", func(o *nativeOffer) {
			o.xcodeOK = func() bool { return false }
			o.interactive = false
		}, offerHint},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := newFakeOffer(&offerFake{}, "")
			c.mod(o)
			if got := o.decide(); got != c.want {
				t.Fatalf("decide() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestNativeOfferAnswers(t *testing.T) {
	cases := []struct {
		answer             string
		installs, declines int
	}{
		{"\n", 1, 0}, // default yes
		{"y\n", 1, 0},
		{"YES\n", 1, 0},
		{"n\n", 0, 1},
		{"no\n", 0, 1},
		{"maybe\nn\n", 0, 1}, // re-asks
		{"", 0, 0},           // EOF: skip, ask next time
	}
	for _, c := range cases {
		f := &offerFake{}
		newFakeOffer(f, c.answer).run()
		if f.installCalls != c.installs || f.saveCalls != c.declines {
			t.Errorf("answer %q: installs=%d declines=%d, want %d/%d", c.answer, f.installCalls, f.saveCalls, c.installs, c.declines)
		}
	}
}

func TestNativeOfferPromptMentionsEssentials(t *testing.T) {
	f := &offerFake{}
	newFakeOffer(f, "n\n").run()
	for _, s := range []string{"iOS", "Xcode", "_clux", "background service", "network rule", "password", "sudo clux native uninstall", "[Y/n]", "sudo clux native install"} {
		if !strings.Contains(f.out.String(), s) {
			t.Errorf("output lacks %q:\n%s", s, f.out.String())
		}
	}
}

func TestNativeOfferInstallFailureContinues(t *testing.T) {
	f := &offerFake{installErr: errors.New("exit status 1")}
	newFakeOffer(f, "y\n").run()
	if !strings.Contains(f.out.String(), "Docker workspaces only") || !strings.Contains(f.out.String(), "exit status 1") {
		t.Fatalf("missing failure message:\n%s", f.out.String())
	}
}

func TestNativeOfferNonInteractiveLogsHintOnly(t *testing.T) {
	f := &offerFake{}
	o := newFakeOffer(f, "y\n")
	o.interactive = false
	o.run()
	if f.installCalls != 0 || f.out.Len() != 0 {
		t.Fatalf("non-interactive run prompted or installed: %q", f.out.String())
	}
	if len(f.logs) != 1 || !strings.Contains(f.logs[0], "sudo clux native install") {
		t.Fatalf("want one hint log line, got %q", f.logs)
	}
}

func TestNativeOfferXcodeMissingSkips(t *testing.T) {
	f := &offerFake{}
	o := newFakeOffer(f, "y\n")
	o.xcodeOK = func() bool { return false }
	o.run()
	if f.installCalls != 0 || f.saveCalls != 0 || !strings.Contains(f.out.String(), "needs Xcode") {
		t.Fatalf("installs=%d saves=%d out=%q", f.installCalls, f.saveCalls, f.out.String())
	}
}

func TestNativeOfferUnhealthyWarnsWithDoctorHint(t *testing.T) {
	f := &offerFake{healthErr: errors.New("supervisor not reachable")}
	o := newFakeOffer(f, "")
	o.installed = func() bool { return true }
	o.run()
	if f.installCalls != 0 || f.out.Len() != 0 {
		t.Fatal("installed: must not prompt")
	}
	if len(f.logs) != 1 || !strings.Contains(f.logs[0], "clux doctor") {
		t.Fatalf("want one warning with doctor hint, got %q", f.logs)
	}

	f2 := &offerFake{}
	o2 := newFakeOffer(f2, "")
	o2.installed = func() bool { return true }
	o2.run()
	if f2.healthCalls != 1 || len(f2.logs) != 0 {
		t.Fatalf("healthy: want no log, got %q", f2.logs)
	}
}

func TestNativeOfferNonDarwinIsSilent(t *testing.T) {
	f := &offerFake{}
	o := newFakeOffer(f, "y\n")
	o.goos = "linux"
	o.run()
	if f.installCalls+f.saveCalls+f.healthCalls != 0 || len(f.logs) != 0 || f.out.Len() != 0 {
		t.Fatal("non-darwin must do nothing")
	}
}
