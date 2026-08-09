package api

import (
	"bytes"
	"strings"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type strictJSONRequest struct {
	Revision string `json:"revision"`
}

func TestDecodeRequestJSONUsesStrictBoundedStateCodec(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		limit   int64
		wantErr bool
	}{
		{name: "valid", body: []byte(`{"revision":"current"}`), limit: 64},
		{name: "unknown field", body: []byte(`{"revision":"current","revisoin":"typo"}`), limit: 64, wantErr: true},
		{name: "duplicate field", body: []byte(`{"revision":"first","Revision":"second"}`), limit: 64, wantErr: true},
		{name: "trailing value", body: []byte(`{"revision":"current"}{}`), limit: 64, wantErr: true},
		{name: "invalid UTF-8", body: append([]byte(`{"revision":"`), 0xff, '"', '}'), limit: 64, wantErr: true},
		{name: "oversized", body: []byte(strings.Repeat(" ", 65)), limit: 64, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(test.body))
			var decoded strictJSONRequest
			err := decodeRequestJSON(request, test.limit, &decoded)
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeRequestJSON error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && decoded.Revision != "current" {
				t.Fatalf("decoded revision = %q", decoded.Revision)
			}
		})
	}
}
