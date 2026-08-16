package api

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/5gpn/dns"
)

func TestDNSGatewayIsReadOnlyThroughWholeDocumentAPI(t *testing.T) {
	svc, err := dns.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		svc.Shutdown(context.Background())
		SetDNSService(nil)
	})
	SetDNSService(svc)
	router := dnsRouter()

	readResponse := httptest.NewRecorder()
	router.ServeHTTP(readResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	if readResponse.Code != http.StatusOK {
		t.Fatalf("GET /5gpn/dns status = %d", readResponse.Code)
	}
	var current dnsResponse
	if err := json.Unmarshal(readResponse.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}

	changed := current.Document
	changed.Gateway = "198.51.100.8"
	changedBody, err := json.Marshal(dnsWriteRequest{Revision: current.Revision, Document: changed})
	if err != nil {
		t.Fatal(err)
	}
	rejected := httptest.NewRecorder()
	router.ServeHTTP(rejected, httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(changedBody)))
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("gateway PUT status = %d, want %d", rejected.Code, http.StatusBadRequest)
	}
	afterRejected, afterRevision := svc.Document()
	if afterRevision != current.Revision || afterRejected.Gateway != current.Document.Gateway {
		t.Fatalf("rejected gateway PUT changed document: revision=%q gateway=%q", afterRevision, afterRejected.Gateway)
	}

	roundTripBody, err := json.Marshal(dnsWriteRequest{Revision: current.Revision, Document: current.Document})
	if err != nil {
		t.Fatal(err)
	}
	accepted := httptest.NewRecorder()
	router.ServeHTTP(accepted, httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(roundTripBody)))
	if accepted.Code != http.StatusOK {
		t.Fatalf("round-trip PUT status = %d, want %d: %s", accepted.Code, http.StatusOK, accepted.Body.String())
	}
}
