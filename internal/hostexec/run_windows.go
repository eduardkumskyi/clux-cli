//go:build windows

package hostexec

// run is never reached on Windows (Start refuses first).
func (e *Executor) run(req Request) Result {
	return Result{Error: "host commands are not supported on Windows"}
}
