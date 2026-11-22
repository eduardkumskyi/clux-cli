//go:build !windows

package hostexec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// run executes req in the owner's login shell and waits for it.
func (e *Executor) run(req Request) Result {
	shell := loginShell()
	if e.shell != nil {
		shell = e.shell()
	}
	out := &tail{limit: req.OutputLimit}
	cmd := exec.Command(shell, "-lc", req.Command)
	cmd.Dir = req.Dir
	cmd.Env = append(os.Environ(), "NONINTERACTIVE=1", "CLUX_HOST_EXEC=1")
	// Stdin stays nil: /dev/null, so nothing can wait for input.
	cmd.Stdout = out
	cmd.Stderr = out
	// Own process group: a timeout kills everything the command started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = waitDelay

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{Error: "could not start: " + err.Error(), Duration: time.Since(started)}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var (
		err      error
		timedOut bool
	)
	timer := time.NewTimer(req.Timeout)
	select {
	case err = <-done:
		timer.Stop()
	case <-timer.C:
		timedOut = true
		pgid := cmd.Process.Pid
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
		grace := killGrace
		if e.grace > 0 {
			grace = e.grace
		}
		select {
		case err = <-done:
		case <-time.After(grace):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			err = <-done
		}
	}
	res := Result{Duration: time.Since(started), TimedOut: timedOut}
	res.Output, res.Truncated = out.text()
	if timedOut {
		res.Error = fmt.Sprintf("timed out after %s", req.Timeout)
		return res
	}
	if st := cmd.ProcessState; st != nil && st.Exited() {
		code := st.ExitCode()
		res.ExitCode = &code
		return res
	}
	if err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		res.Error = err.Error()
	}
	return res
}
