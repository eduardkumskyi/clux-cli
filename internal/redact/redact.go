// Package redact masks secrets in text that is about to be logged or sent
// back to the backend: values of sensitive environment variables
// (SIDECAR_HMAC_SECRET=..., GH_TOKEN=...), passwords in URL userinfo
// (http://ws-<id>:<password>@127.0.0.1:P) and bearer tokens. Everything
// else is left as is, so redacted lines stay useful for diagnosis.
package redact

import (
	"regexp"
	"strings"
)

// Mask replaces a secret value.
const Mask = "[REDACTED]"

var (
	sensitiveKey = regexp.MustCompile(`(?i)(secret|token|password|passwd|key|auth|credential)`)
	envName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// scheme://user:password@ and scheme://user@ (a token used as the user
	// name, as in https://<token>@github.com).
	userinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)([^/\s:@]*)(:[^/\s@]*)?@`)
	// KEY=value in free text (a command line, an env dump).
	envPair = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s"',;&]+)`)
	// "key": "value" in JSON-ish text.
	jsonPair = regexp.MustCompile(`"([A-Za-z0-9_.-]*)"(\s*:\s*)"(?:[^"\\]|\\.)*"`)
	bearer   = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+`)
)

// SensitiveKey reports whether an env/field name looks like it holds a
// secret.
func SensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }

// URL masks the userinfo of every URL in s: the password when there is
// one (the user name stays, e.g. ws-<id>), else the user name itself.
func URL(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	return userinfo.ReplaceAllStringFunc(s, func(m string) string {
		sub := userinfo.FindStringSubmatch(m)
		scheme, user, pass := sub[1], sub[2], sub[3]
		if pass != "" {
			return scheme + user + ":" + Mask + "@"
		}
		if user == "" {
			return m
		}
		return scheme + Mask + "@"
	})
}

// Env redacts one KEY=VALUE pair: the whole value for a sensitive key, URL
// userinfo for any other.
func Env(kv string) string {
	k, v, ok := strings.Cut(kv, "=")
	if !ok || !envName.MatchString(k) {
		return URL(kv)
	}
	if SensitiveKey(k) {
		return k + "=" + Mask
	}
	return k + "=" + URL(v)
}

// EnvList redacts an environment ([]string of KEY=VALUE) into a copy.
func EnvList(env []string) []string {
	out := make([]string, len(env))
	for i, kv := range env {
		out[i] = Env(kv)
	}
	return out
}

// Args redacts a command's arguments into a copy: KEY=VALUE arguments (the
// operand of -e/--env, --env=KEY=VALUE, `env KEY=VALUE cmd`) and URL
// userinfo anywhere.
func Args(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		switch {
		case strings.HasPrefix(a, "--env="):
			out[i] = "--env=" + Env(strings.TrimPrefix(a, "--env="))
		case strings.HasPrefix(a, "-e") && len(a) > 2 && strings.Contains(a, "="):
			out[i] = "-e" + Env(a[2:])
		default:
			out[i] = Env(a)
		}
	}
	return out
}

// String redacts free text: URL userinfo, sensitive KEY=VALUE pairs,
// sensitive "key": "value" JSON fields and bearer tokens.
func String(s string) string {
	s = URL(s)
	if strings.Contains(s, "=") {
		s = envPair.ReplaceAllStringFunc(s, func(m string) string {
			k, _, _ := strings.Cut(m, "=")
			if SensitiveKey(k) {
				return k + "=" + Mask
			}
			return m
		})
	}
	if strings.Contains(s, `"`) {
		s = jsonPair.ReplaceAllStringFunc(s, func(m string) string {
			sub := jsonPair.FindStringSubmatch(m)
			if SensitiveKey(sub[1]) {
				return `"` + sub[1] + `"` + sub[2] + `"` + Mask + `"`
			}
			return m
		})
	}
	return bearer.ReplaceAllString(s, "$1 "+Mask)
}
