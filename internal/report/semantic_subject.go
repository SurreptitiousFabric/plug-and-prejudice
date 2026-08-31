package report

import "strconv"

const resourceComparisonSubjectVersion = "resource-subject/v1"

// resourceComparisonSubject is an injective textual encoding of exactly the
// resource fields that define comparison identity. Each UTF-8 field is
// preceded by its decimal byte length, so hostile separators and control
// characters cannot move bytes between fields.
func resourceComparisonSubject(kind, access, value string) string {
	result := make([]byte, 0, len(resourceComparisonSubjectVersion)+len(kind)+len(access)+len(value)+32)
	result = append(result, resourceComparisonSubjectVersion...)
	for _, field := range []string{kind, access, value} {
		result = append(result, ':')
		result = strconv.AppendInt(result, int64(len(field)), 10)
		result = append(result, ':')
		result = append(result, field...)
	}
	return string(result)
}
