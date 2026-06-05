package inject

import (
	"fmt"
	"strings"
)

type placeholder struct {
	Start int
	End   int
	Raw   string
	Inner string
}

type ParseError struct {
	Offset int
	Msg    string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("template parse error at byte %d: %s", e.Offset, e.Msg)
}

func parsePlaceholdersStrict(input string) ([]placeholder, error) {
	var result []placeholder
	pos := 0

	for pos < len(input) {
		nextOpen := strings.Index(input[pos:], "{{")
		nextClose := strings.Index(input[pos:], "}}")

		if nextOpen == -1 && nextClose == -1 {
			break
		}
		if nextClose != -1 && (nextOpen == -1 || nextClose < nextOpen) {
			return nil, ParseError{
				Offset: pos + nextClose,
				Msg:    "found '}}' without matching '{{'",
			}
		}

		start := pos + nextOpen
		contentStart := start + 2
		closeRel := strings.Index(input[contentStart:], "}}")
		if closeRel == -1 {
			return nil, ParseError{
				Offset: start,
				Msg:    "found '{{' without matching '}}'",
			}
		}

		contentEnd := contentStart + closeRel
		end := contentEnd + 2
		innerRaw := input[contentStart:contentEnd]

		if nested := strings.Index(innerRaw, "{{"); nested != -1 {
			return nil, ParseError{
				Offset: contentStart + nested,
				Msg:    "found nested '{{' inside placeholder",
			}
		}

		result = append(result, placeholder{
			Start: start,
			End:   end,
			Raw:   input[start:end],
			Inner: strings.TrimSpace(innerRaw),
		})
		pos = end
	}

	return result, nil
}
