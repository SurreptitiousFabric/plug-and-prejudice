package analyze

import (
	"strconv"
	"strings"

	"github.com/SurreptitiousFabric/plug-and-prejudice/internal/report"
)

const (
	maxQMLAssignments     = 1024
	maxQMLResolutionDepth = 16
)

type qmlLiteralAssignment struct {
	name       string
	expression string
	origin     report.ValueOrigin
}

// qmlRootLiteralAssignments indexes only property declarations at brace depth
// one (the root object's own properties). Nested object properties are excluded
// so lexical lookalikes and shadowed names cannot be selected accidentally.
func qmlRootLiteralAssignments(name string, data []byte, lines sourceIndex) (map[string][]qmlLiteralAssignment, bool) {
	assignments := make(map[string][]qmlLiteralAssignment)
	complete := true
	count := 0
	depth := 0
	for index := 0; index < len(data); {
		index = skipQMLSpaceAndComments(data, index)
		if index >= len(data) {
			break
		}
		if data[index] == '"' || data[index] == '\'' || data[index] == '`' {
			index = skipQMLString(data, index)
			continue
		}
		switch data[index] {
		case '{':
			depth++
			index++
			continue
		case '}':
			if depth > 0 {
				depth--
			}
			index++
			continue
		}
		if !isIdentifierStart(rune(data[index])) {
			index++
			continue
		}
		start := index
		index++
		for index < len(data) && isIdentifierPart(rune(data[index])) {
			index++
		}
		if depth != 1 || string(data[start:index]) != "property" {
			continue
		}
		afterType, propertyType, ok := qmlIdentifierAt(data, index)
		if !ok || (propertyType != "var" && propertyType != "string") {
			continue
		}
		afterName, propertyName, ok := qmlIdentifierAt(data, afterType)
		if !ok {
			continue
		}
		colon := skipQMLSpaceAndComments(data, afterName)
		if colon >= len(data) || data[colon] != ':' {
			continue
		}
		expressionStart := skipQMLSpaceAndComments(data, colon+1)
		expressionEnd, ok := qmlLiteralExpressionEnd(data, expressionStart)
		if !ok {
			continue
		}
		count++
		if count > maxQMLAssignments {
			complete = false
			continue
		}
		line := lines.lineAt(start)
		evidence := report.Evidence{Path: name, LineStart: line, LineEnd: lines.lineAt(expressionEnd), Operation: "property " + propertyName, Excerpt: lines.line(line)}
		assignments[propertyName] = append(assignments[propertyName], qmlLiteralAssignment{
			name: propertyName, expression: strings.TrimSpace(string(data[expressionStart:expressionEnd])),
			origin: report.ValueOrigin{Kind: report.OriginPropertyAssignment, Name: propertyName, Evidence: evidence},
		})
		index = expressionEnd
	}
	return assignments, complete
}

func qmlIdentifierAt(data []byte, start int) (int, string, bool) {
	index := skipQMLSpaceAndComments(data, start)
	if index >= len(data) || !isIdentifierStart(rune(data[index])) {
		return start, "", false
	}
	begin := index
	index++
	for index < len(data) && isIdentifierPart(rune(data[index])) {
		index++
	}
	return index, string(data[begin:index]), true
}

func qmlLiteralExpressionEnd(data []byte, start int) (int, bool) {
	if start >= len(data) {
		return start, false
	}
	if data[start] == '[' {
		end, ok := matchQMLDelimiter(data, start, '[', ']')
		return end + 1, ok
	}
	if data[start] == '"' || data[start] == '\'' {
		end := skipQMLString(data, start)
		return end, end > start && end <= len(data)
	}
	end := start
	for end < len(data) && data[end] != '\n' && data[end] != '\r' && data[end] != ';' && data[end] != '}' {
		end++
	}
	return end, end > start
}

func resolveQMLCommandExpression(expression string, assignments map[string][]qmlLiteralAssignment) (string, []string, []report.ValueOrigin, bool) {
	values, origins, ok := resolveQMLLiteral(expression, assignments, make(map[string]bool), 0)
	if !ok || len(values) == 0 || len(values) > maxRetainedArguments+1 {
		return "", nil, origins, false
	}
	return values[0], values[1:], origins, true
}

func resolveQMLLiteral(expression string, assignments map[string][]qmlLiteralAssignment, seen map[string]bool, depth int) ([]string, []report.ValueOrigin, bool) {
	if depth >= maxQMLResolutionDepth {
		return nil, nil, false
	}
	trimmed := strings.TrimSpace(expression)
	if value, ok := qmlQuotedLiteral(trimmed); ok {
		if len(value) > maxRetainedStringBytes {
			return nil, nil, false
		}
		return []string{value}, nil, true
	}
	if qmlPlainIdentifier(trimmed) {
		definitions := assignments[trimmed]
		if len(definitions) != 1 || seen[trimmed] {
			return nil, qmlDefinitionOrigins(definitions), false
		}
		seen[trimmed] = true
		values, origins, ok := resolveQMLLiteral(definitions[0].expression, assignments, seen, depth+1)
		delete(seen, trimmed)
		return values, append([]report.ValueOrigin{definitions[0].origin}, origins...), ok
	}
	if !strings.HasPrefix(trimmed, "[") || !strings.HasSuffix(trimmed, "]") {
		return nil, nil, false
	}
	elements, ok := qmlLiteralArrayElements(trimmed[1 : len(trimmed)-1])
	if !ok || len(elements) == 0 || len(elements) > maxRetainedArguments+1 {
		return nil, nil, false
	}
	values := make([]string, 0, len(elements))
	origins := make([]report.ValueOrigin, 0)
	for _, element := range elements {
		part, partOrigins, resolved := resolveQMLLiteral(element, assignments, seen, depth+1)
		origins = appendBoundedOrigins(origins, partOrigins)
		if !resolved || len(part) != 1 {
			return nil, origins, false
		}
		values = append(values, part[0])
	}
	return values, origins, true
}

func qmlLiteralArrayElements(body string) ([]string, bool) {
	elements := make([]string, 0, 8)
	start := 0
	quote := byte(0)
	escaped := false
	for index := 0; index <= len(body); index++ {
		if index == len(body) || (quote == 0 && body[index] == ',') {
			element := strings.TrimSpace(body[start:index])
			if element != "" {
				elements = append(elements, element)
			}
			start = index + 1
			continue
		}
		character := body[index]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == quote {
				quote = 0
			}
			continue
		}
		if character == '"' || character == '\'' {
			quote = character
		}
	}
	return elements, quote == 0 && !escaped
}

func qmlQuotedLiteral(value string) (string, bool) {
	if len(value) < 2 || (value[0] != '"' && value[0] != '\'') || value[len(value)-1] != value[0] {
		return "", false
	}
	decoded, err := strconv.Unquote(value)
	if err == nil {
		return decoded, true
	}
	if value[0] == '\'' {
		return value[1 : len(value)-1], !strings.Contains(value[1:len(value)-1], "\\")
	}
	return "", false
}

func qmlPlainIdentifier(value string) bool {
	if value == "" || !isIdentifierStart(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if !isIdentifierPart(character) {
			return false
		}
	}
	return true
}

func qmlDefinitionOrigins(definitions []qmlLiteralAssignment) []report.ValueOrigin {
	origins := make([]report.ValueOrigin, 0, len(definitions))
	for _, definition := range definitions {
		origins = appendBoundedOrigins(origins, []report.ValueOrigin{definition.origin})
	}
	return origins
}

func appendBoundedOrigins(existing, additions []report.ValueOrigin) []report.ValueOrigin {
	for _, origin := range additions {
		if len(existing) >= report.MaxUnknownOrigins {
			break
		}
		duplicate := false
		for _, retained := range existing {
			if retained.Kind == origin.Kind && retained.Name == origin.Name && retained.Evidence == origin.Evidence {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		existing = append(existing, origin)
	}
	return existing
}
