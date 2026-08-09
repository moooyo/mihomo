package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// MaxDocumentBytes is the hard ceiling for a durable 5gpn JSON document.
// Individual API requests use narrower limits, but an existing file is never
// allowed to make startup allocate without a bound.
const MaxDocumentBytes int64 = 16 << 20

const maxJSONNesting = 128

// DecodeJSON reads one bounded, strict JSON value into dst.
//
// It is shared by the controller and durable state so a body accepted through
// the API cannot acquire different semantics after it is written and reopened.
func DecodeJSON(r io.Reader, maxBytes int64, dst any) error {
	raw, err := readAllBounded(r, maxBytes)
	if err != nil {
		return err
	}
	return DecodeJSONBytes(raw, maxBytes, dst)
}

// DecodeJSONBytes strictly decodes one already-buffered JSON value.
func DecodeJSONBytes(raw []byte, maxBytes int64, dst any) error {
	if err := ValidateJSONBytes(raw, maxBytes); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("5gpn/state: decode JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("5gpn/state: decode JSON: %w", err)
	}
	return nil
}

// ValidateJSONBytes validates the bounded JSON envelope without applying a
// destination schema. It exists for documents that must remove an explicitly
// retired field before their current-schema decode; malformed encoding,
// duplicate keys, and trailing values are still rejected before that rewrite.
func ValidateJSONBytes(raw []byte, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("5gpn/state: JSON byte limit must be positive")
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("5gpn/state: JSON exceeds %d bytes", maxBytes)
	}
	if !utf8.Valid(raw) {
		return errors.New("5gpn/state: JSON is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("5gpn/state: invalid JSON: %w", err)
	}
	return nil
}

func readAllBounded(r io.Reader, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("5gpn/state: JSON byte limit must be positive")
	}
	if maxBytes == int64(^uint64(0)>>1) {
		return nil, errors.New("5gpn/state: JSON byte limit is too large")
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("5gpn/state: read JSON: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("5gpn/state: JSON exceeds %d bytes", maxBytes)
	}
	return raw, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONNesting {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONNesting)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			// encoding/json matches struct field names case-insensitively. Treat
			// two spellings that target the same field as duplicates too.
			canonical := strings.ToLower(key)
			if _, exists := keys[canonical]; exists {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			keys[canonical] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object has an invalid closing delimiter")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array has an invalid closing delimiter")
		}
		return nil
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON contains multiple values")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}
