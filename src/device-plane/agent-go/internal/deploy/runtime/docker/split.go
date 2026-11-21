package docker

import (
	"errors"
	"strings"
)

// Split splits a command line into arguments like Python's shlex.split (POSIX
// mode), which the Python agent used for a docker release's command: blanks
// separate, single quotes keep everything, inside double quotes a backslash
// escapes only " and \, and elsewhere it escapes the next character. Nothing
// is expanded.
func Split(s string) ([]string, error) {
	var (
		args   []string
		cur    strings.Builder
		inArg  bool
		quote  rune // 0, '\'' or '"'
		escape bool
	)
	for _, r := range s {
		switch {
		case escape:
			if quote == '"' && r != '"' && r != '\\' {
				cur.WriteRune('\\')
			}
			cur.WriteRune(r)
			escape, inArg = false, true
		case quote == '\'':
			if r == '\'' {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case quote == '"':
			switch r {
			case '"':
				quote = 0
			case '\\':
				escape = true
			default:
				cur.WriteRune(r)
			}
		case r == '\\':
			escape, inArg = true, true
		case r == '\'' || r == '"':
			quote, inArg = r, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		default:
			cur.WriteRune(r)
			inArg = true
		}
	}
	if escape {
		return nil, errors.New("no escaped character")
	}
	if quote != 0 {
		return nil, errors.New("no closing quotation")
	}
	if inArg {
		args = append(args, cur.String())
	}
	return args, nil
}
