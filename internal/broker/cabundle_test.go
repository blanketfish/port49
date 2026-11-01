package broker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
)

// GET /v1/config carries the CA bundle the broker was given, no field at all
// with none, and broker_ca_bundle_refused for one it refused (decision 43
// ruling 25).
func TestConfigCarriesTheCABundle(t *testing.T) {
	b := &Broker{MaxSessionAge: time.Hour, CABundle: []byte("-----BEGIN CERTIFICATE-----\n")}
	rec := httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || c.BrokerCABundle != "-----BEGIN CERTIFICATE-----\n" {
		t.Fatalf("%v %q", err, rec.Body.String())
	}
	b.CABundle = nil
	rec = httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	if strings.Contains(rec.Body.String(), "broker_ca_bundle") {
		t.Fatalf("%q", rec.Body.String())
	}
	// A bundle configured and refused at start is said, so clients keep what
	// they hold.
	b.CABundleRefused = true
	rec = httptest.NewRecorder()
	b.config(rec, httptest.NewRequest(http.MethodGet, "/v1/config", nil))
	c = api.Config{}
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil || !c.BrokerCABundleRefused || c.BrokerCABundle != "" {
		t.Fatalf("%v %q", err, rec.Body.String())
	}
}
