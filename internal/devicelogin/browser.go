package devicelogin

import (
	"errors"
	"os/exec"
	"runtime"
)

// BrowserCommand is the OS command that opens rawURL in the default
// browser, or nil where there is none.
func BrowserCommand(goos, rawURL string) []string {
	switch goos {
	case "darwin":
		return []string{"open", rawURL}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", rawURL}
	case "linux", "freebsd", "openbsd", "netbsd":
		return []string{"xdg-open", rawURL}
	}
	return nil
}

// OpenBrowser tries to open rawURL; failure is fine (a server without a
// desktop), the URL is printed anyway. It does not wait for the browser.
func OpenBrowser(rawURL string) error {
	if !isWebURL(rawURL) {
		return errors.New("not a web URL")
	}
	argv := BrowserCommand(runtime.GOOS, rawURL)
	if argv == nil {
		return errors.New("no browser opener on " + runtime.GOOS)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
