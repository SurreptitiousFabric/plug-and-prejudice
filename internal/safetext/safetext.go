package safetext

import (
	"strings"
	"unicode/utf8"
)

const truncationMarker = "...[truncated]"

// Diagnostic converts hostile bytes to terminal/UI-safe plain text and bounds
// the result before it crosses a process boundary. Output never exceeds limit
// bytes. Newline and tab remain readable; other C0/C1 and bidi controls are
// replaced with '?'.
func Diagnostic(data []byte, limit int) string {
	if limit <= 0 {
		return ""
	}
	contentLimit := limit
	truncated := len(data) > limit
	if truncated {
		contentLimit -= len(truncationMarker)
		if contentLimit < 0 {
			contentLimit = 0
		}
	}

	var output strings.Builder
	output.Grow(min(limit, len(data)))
	written := 0
	for len(data) > 0 {
		value, size := utf8.DecodeRune(data)
		replacement := value == utf8.RuneError && size == 1 || forbiddenRune(value)
		encodedSize := size
		if replacement {
			encodedSize = 1
		}
		if written+encodedSize > contentLimit {
			truncated = true
			break
		}
		if replacement {
			output.WriteByte('?')
		} else {
			output.WriteRune(value)
		}
		written += encodedSize
		data = data[size:]
	}
	if truncated {
		remaining := limit - written
		if remaining > len(truncationMarker) {
			remaining = len(truncationMarker)
		}
		output.WriteString(truncationMarker[:remaining])
	}
	return output.String()
}

func forbiddenRune(value rune) bool {
	return (value < 0x20 && value != '\n' && value != '\t') ||
		(value >= 0x7f && value <= 0x9f) ||
		value == 0x061c || value == 0x200e || value == 0x200f ||
		(value >= 0x202a && value <= 0x202e) ||
		(value >= 0x2066 && value <= 0x2069)
}
