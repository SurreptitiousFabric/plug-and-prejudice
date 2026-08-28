// Package boundedjson encodes trusted typed values without allowing an
// unbounded temporary JSON document or exposing partial output to a consumer.
package boundedjson

import (
	"encoding/json"
	"errors"
)

var ErrLimitExceeded = errors.New("encoded JSON exceeds byte limit")

type buffer struct {
	bytes []byte
	limit int
}

func (b *buffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-len(b.bytes) {
		return 0, ErrLimitExceeded
	}
	b.bytes = append(b.bytes, value...)
	return len(value), nil
}

// Encode returns a complete JSON document including the encoder's trailing
// newline. No bytes are returned if encoding fails or crosses limit.
func Encode(value any, limit int, indent string) ([]byte, error) {
	if limit < 1 {
		return nil, ErrLimitExceeded
	}
	destination := &buffer{limit: limit}
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(true)
	if indent != "" {
		encoder.SetIndent("", indent)
	}
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return destination.bytes, nil
}
