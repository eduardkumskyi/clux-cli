package hostexec

import (
	"path/filepath"
	"strings"
)

// passwordCommands ask for a password on a terminal, which a host command
// (stdin is /dev/null) can never answer.
var passwordCommands = map[string]bool{"sudo": true, "su": true, "doas": true, "pkexec": true}

// prefixWords run the word after them as the command (env/exec/... and shell
// keywords), so the word after them is in command position too.
var prefixWords = map[string]bool{
	"env": true, "exec": true, "command": true, "builtin": true, "nohup": true,
	"time": true, "nice": true, "xargs": true, "caffeinate": true,
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "{": true,
}

// NeedsPassword reports whether command runs sudo, su, doas or pkexec in
// command position: at its start, after a separator (; & | ( ) ` newline,
// which also covers &&, || and $(...)), or after a prefix such as env, exec
// or command. It is a plain tokenizer, not a shell parser, and errs on the
// side of saying yes.
func NeedsPassword(command string) bool {
	segments := strings.FieldsFunc(command, func(r rune) bool {
		switch r {
		case ';', '&', '|', '(', ')', '`', '\n', '\r', '{', '}':
			return true
		}
		return false
	})
	for _, segment := range segments {
		for _, raw := range strings.Fields(segment) {
			word := strings.TrimLeft(raw, "$")
			word = strings.Trim(word, `"'\`)
			if word == "" {
				continue
			}
			if passwordCommands[filepath.Base(word)] {
				return true
			}
			// NAME=value assignments, prefix words and their options keep
			// the next word in command position.
			if prefixWords[word] || strings.HasPrefix(word, "-") || isAssignment(word) || isNumber(word) {
				continue
			}
			break
		}
	}
	return false
}

// isNumber: an option's value such as nice's "-n 10".
func isNumber(word string) bool {
	for _, r := range word {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}
