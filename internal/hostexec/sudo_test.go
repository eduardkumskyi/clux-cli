package hostexec

import "testing"

func TestNeedsPassword(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"brew install android-commandlinetools", false},
		{"sudo softwareupdate -i -a", true},
		{"  sudo -n true", true},
		{"/usr/bin/sudo ls", true},
		{`"sudo" ls`, true},
		{`\sudo ls`, true},
		{"echo hi; sudo ls", true},
		{"make && sudo make install", true},
		{"false || doas reboot", true},
		{"cat x | sudo tee /etc/hosts", true},
		{"echo $(sudo whoami)", true},
		{"echo `su -c id`", true},
		{"(pkexec id)", true},
		{"ls\nsudo ls", true},
		{"env FOO=1 sudo ls", true},
		{"FOO=bar sudo ls", true},
		{"exec sudo ls", true},
		{"command sudo ls", true},
		{"nice -n 10 sudo ls", true},
		{"if true; then sudo ls; fi", true},
		{"echo sudo", false},
		{"grep -r sudo .", false},
		{"brew install sudo-helper", false},
		{"pseudo-tool run", false},
		{"suspend-app", false},
		{"git commit -m 'use su later'", false},
	}
	for _, c := range cases {
		if got := NeedsPassword(c.command); got != c.want {
			t.Errorf("NeedsPassword(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}
