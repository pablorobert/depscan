// Package jsonc converts JSON-with-comments-and-trailing-commas into strict JSON.
//
// bun.lock needs this: it is JSONC, and encoding/json rejects it. Measured with bun
// 1.4.2, a strict parse fails on the trailing comma before a closing brace.
package jsonc

import "bytes"

// Strip rewrites src into strict JSON by removing // and /* */ comments and commas that
// directly precede a closing brace or bracket. Bytes inside string literals are copied
// untouched, escapes included.
func Strip(src []byte) []byte {
	out := make([]byte, 0, len(src))
	// lastValue indexes the most recent non-whitespace byte written to out, so a comma
	// can be retracted once we discover what follows it.
	lastValue := -1

	for i := 0; i < len(src); {
		c := src[i]

		switch {
		case c == '"':
			start := i
			i++
			for i < len(src) {
				if src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == '"' {
					i++
					break
				}
				i++
			}
			out = append(out, src[start:i]...)
			lastValue = len(out) - 1

		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}

		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i += 2
			if i > len(src) {
				i = len(src)
			}

		case c == '}' || c == ']':
			// Retract a trailing comma: it is the last written value byte.
			if lastValue >= 0 && out[lastValue] == ',' {
				out = out[:lastValue]
				out = bytes.TrimRight(out, " \t\r\n")
			}
			out = append(out, c)
			lastValue = len(out) - 1
			i++

		default:
			out = append(out, c)
			if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
				lastValue = len(out) - 1
			}
			i++
		}
	}
	return out
}
