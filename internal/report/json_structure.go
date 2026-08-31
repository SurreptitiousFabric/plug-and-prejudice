package report

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

var textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

// validateJSONStructure rejects Unicode normalization and enforces exact
// schema member names before encoding/json can apply case-insensitive lookup.
func validateJSONStructure(data []byte, target reflect.Type) error {
	if !utf8.Valid(data) {
		return errors.New("JSON input is not valid UTF-8")
	}
	if err := validateSurrogateEscapes(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeTypedJSONValue(decoder, target, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values after %v", token)
		}
		return err
	}
	return nil
}

func consumeTypedJSONValue(decoder *json.Decoder, target reflect.Type, depth int) error {
	if depth > MaxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds limit %d", MaxJSONDepth)
	}
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	atomic := reflect.PointerTo(target).Implements(textUnmarshalerType)
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	if atomic {
		return fmt.Errorf("%s must be encoded as one scalar JSON value", target)
	}
	switch delimiter {
	case '{':
		if target.Kind() != reflect.Struct && target.Kind() != reflect.Map {
			target = reflect.TypeOf(map[string]any{})
		}
		var fields map[string]reflect.Type
		if target.Kind() == reflect.Struct {
			fields = exactJSONFields(target)
		}
		seen := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[name]; exists {
				return fmt.Errorf("duplicate JSON object member %q", name)
			}
			seen[name] = struct{}{}
			var valueType reflect.Type
			if target.Kind() == reflect.Map {
				valueType = target.Elem()
			} else {
				var exists bool
				valueType, exists = fields[name]
				if !exists {
					return fmt.Errorf("unknown or incorrectly cased JSON member %q for %s", name, target)
				}
			}
			if err := consumeTypedJSONValue(decoder, valueType, depth+1); err != nil {
				return err
			}
		}
	case '[':
		if target.Kind() != reflect.Slice && target.Kind() != reflect.Array {
			target = reflect.TypeOf([]any{})
		}
		for decoder.More() {
			if err := consumeTypedJSONValue(decoder, target.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	closing, err := decoder.Token()
	if err != nil {
		return err
	}
	want := json.Delim('}')
	if delimiter == '[' {
		want = ']'
	}
	if closing != want {
		return fmt.Errorf("mismatched JSON delimiter %q", closing)
	}
	return nil
}

func exactJSONFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, target.NumField())
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" {
			name = field.Name
		}
		if name != "-" {
			fields[name] = field.Type
		}
	}
	return fields
}

func validateSurrogateEscapes(data []byte) error {
	inString, escaped := false, false
	for index := 0; index < len(data); index++ {
		value := data[index]
		if !inString {
			if value == '"' {
				inString = true
			}
			continue
		}
		if escaped {
			escaped = false
			if value != 'u' {
				continue
			}
			code, next, err := parseUnicodeEscape(data, index-1)
			if err != nil {
				return err
			}
			index = next - 1
			if code >= 0xd800 && code <= 0xdbff {
				if next+6 > len(data) || data[next] != '\\' || data[next+1] != 'u' {
					return errors.New("unpaired high UTF-16 surrogate escape")
				}
				low, after, err := parseUnicodeEscape(data, next)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return errors.New("malformed UTF-16 surrogate pair")
				}
				index = after - 1
			} else if code >= 0xdc00 && code <= 0xdfff {
				return errors.New("unpaired low UTF-16 surrogate escape")
			}
			continue
		}
		if value == '\\' {
			escaped = true
		} else if value == '"' {
			inString = false
		}
	}
	return nil
}

func parseUnicodeEscape(data []byte, slash int) (uint64, int, error) {
	if slash+6 > len(data) || data[slash] != '\\' || data[slash+1] != 'u' {
		return 0, slash, errors.New("malformed Unicode escape")
	}
	value, err := strconv.ParseUint(string(data[slash+2:slash+6]), 16, 16)
	if err != nil {
		return 0, slash, errors.New("malformed Unicode escape")
	}
	return value, slash + 6, nil
}
