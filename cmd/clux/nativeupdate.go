package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/eduardkumskyi/clux-cli/internal/native"
	"github.com/eduardkumskyi/clux-cli/internal/selfupdate"
)

// The native macOS runtime's daemons run their own root-owned copy of clux.
// From native.FirstSelfUpdatingVersion on they follow this CLI by
// themselves: `clux update` and `clux host start` ask the root daemon (over
// the slot keeper's socket) to move to this CLI's release, and root
// downloads and verifies it itself; no sudo. An older installation needs
// one `sudo clux native install` first.

// nativeDaemons is the native runtime's copy of clux (fake in tests).
type nativeDaemons interface {
	// Installed is the clux version the daemons' binary came from; "" if
	// the native runtime is not installed.
	Installed() string
	Update(ctx context.Context, tag string, allowDowngrade bool) (native.UpdateResult, error)
	WaitForDaemon(ctx context.Context, tag string) error
}

type installedNativeDaemons struct{}

func (installedNativeDaemons) Installed() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	cfg, err := native.LoadConfig()
	if err != nil {
		return ""
	}
	return cfg.CLIVersion
}

func (installedNativeDaemons) keeper() *native.KeeperClient {
	return &native.KeeperClient{Socket: native.KeeperSocket}
}

func (d installedNativeDaemons) Update(ctx context.Context, tag string, allowDowngrade bool) (native.UpdateResult, error) {
	return d.keeper().Update(ctx, tag, allowDowngrade)
}

func (d installedNativeDaemons) WaitForDaemon(ctx context.Context, tag string) error {
	return d.keeper().WaitForDaemon(ctx, tag)
}

// nativeBootstrapNotice: daemons too old to update themselves.
func nativeBootstrapNotice(installed string) string {
	return fmt.Sprintf("The native macOS runtime runs clux %s, which can't update itself. Run `clux update` once in a terminal "+
		"to replace it (macOS asks for your password); after that it follows `clux update` by itself", installed)
}

// nativeBehind says whether the daemons should move to tag: behind it, or
// (explicit, i.e. `clux update --version`) anything else than it.
func nativeBehind(installed, tag string, explicit bool) bool {
	if installed == "" || installed == tag || !selfupdate.ValidTag(tag) {
		return false
	}
	return explicit || selfupdate.Older(installed, tag)
}

// nativeSync is the outcome of syncNativeDaemons.
type nativeSync int

const (
	nativeCurrent   nativeSync = iota // nothing to do (or not installed)
	nativeUpdated                     // moved to the tag (maybe with deferred restarts)
	nativeBootstrap                   // too old to update itself: replaced once, as root
	nativeFailed
)

// syncNativeDaemons moves the native daemons to release tag (to an older
// one only when explicit), reporting through say.
func syncNativeDaemons(ctx context.Context, d nativeDaemons, tag string, explicit bool, say func(string, ...any)) nativeSync {
	installed := d.Installed()
	if !nativeBehind(installed, tag, explicit) {
		return nativeCurrent
	}
	if !native.CanSelfUpdate(installed) {
		say("%s", nativeBootstrapNotice(installed))
		return nativeBootstrap
	}
	say("Updating the native macOS runtime from clux %s to %s...", installed, tag)
	uctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	res, err := d.Update(uctx, tag, explicit)
	if err != nil {
		say("Native runtime update failed: %v", err)
		return nativeFailed
	}
	if res.UpToDate {
		say("The native macOS runtime already runs clux %s.", res.To)
		return nativeUpdated
	}
	msg := fmt.Sprintf("Native macOS runtime updated to clux %s", res.To)
	if len(res.Deferred) > 0 {
		msg += fmt.Sprintf("; slot(s) %s switch over when their running workspace stops", joinInts(res.Deferred))
	}
	if !res.DaemonRestarting {
		say("%s.", msg)
		return nativeUpdated
	}
	wctx, wcancel := context.WithTimeout(ctx, 45*time.Second)
	defer wcancel()
	if err := d.WaitForDaemon(wctx, res.To); err != nil {
		say("%s, but %v", msg, err)
		return nativeUpdated
	}
	say("%s.", msg)
	return nativeUpdated
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}
