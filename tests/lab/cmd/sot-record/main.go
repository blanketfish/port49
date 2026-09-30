// Command sot-record measures what a NetBox or Nautobot API returns for a
// device (spec §15, L27) and writes each response as a fixture under -out.
// It records responses and never the request's Authorization header, so a
// fixture carries no credential; a response or webhook delivery that echoes
// a credential the run holds or was issued has it replaced by "<redacted>". Every call's outcome is recorded, a refusal
// included: a call a version does not take is the finding.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type recorder struct {
	base, token, scheme, product, out string
	legacy                            bool
	client                            *http.Client
	ids                               map[string]any
	secrets                           []string
}

// exchange is one recorded call: what was asked, and everything the server
// answered but the headers that set cookies.
type exchange struct {
	Step    string            `json:"step"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Request json.RawMessage   `json:"request,omitempty"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

func (r *recorder) call(step, method, path string, body any) exchange {
	x, _ := r.callAs(step, method, path, body, r.scheme+" "+r.token, nil)
	return x
}

// callAs is call with the given Authorization value. Each field named in
// learn that the response carries as a string is a credential the product
// just issued: it joins the redacted set before this response is recorded,
// and is returned so a later call can use it.
func (r *recorder) callAs(step, method, path string, body any, auth string, learn []string) (exchange, map[string]string) {
	var reqBody []byte
	if body != nil {
		reqBody, _ = json.Marshal(r.expand(body))
	}
	path = r.expandPath(path)
	req, err := http.NewRequest(method, r.base+path, bytes.NewReader(reqBody))
	if err != nil {
		fail("%s: %v", step, err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		fail("%s: %v", step, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	learned := map[string]string{}
	if len(learn) > 0 {
		var obj map[string]any
		if json.Unmarshal(raw, &obj) == nil {
			for _, f := range learn {
				if s, ok := obj[f].(string); ok && len(s) >= 8 {
					// NetBox's display of a token is its last six characters
					// behind asterisks: the tail is redacted too.
					r.secrets = append(r.secrets, s, s[len(s)-6:])
					learned[f] = s
				}
			}
		}
	}
	raw = r.redact(raw)
	x := exchange{Step: step, Method: method, Path: path, Status: resp.StatusCode, Headers: map[string]string{}}
	if reqBody != nil {
		x.Request = reqBody
	}
	for k, vs := range resp.Header {
		if k != "Set-Cookie" {
			x.Headers[k] = string(r.redact([]byte(strings.Join(vs, ", "))))
		}
	}
	if json.Valid(raw) {
		x.Body = raw
	} else {
		x.Body, _ = json.Marshal(string(raw))
	}
	return x, learned
}

// redact replaces every part of every API credential the run holds or was
// issued in b with "<redacted>".
func (r *recorder) redact(b []byte) []byte {
	for _, s := range r.secrets {
		b = bytes.ReplaceAll(b, []byte(s), []byte("<redacted>"))
	}
	return b
}

// credentialParts is the token and, for a NetBox v2 token (nbt_<key>.<secret>),
// its key and secret, each of which a response could echo on its own.
func credentialParts(token string) []string {
	parts := []string{token}
	if key, secret, ok := strings.Cut(strings.TrimPrefix(token, "nbt_"), "."); ok {
		parts = append(parts, key, secret)
	}
	return parts
}

// legacyTwin names, per product, for -prefer-legacy, the step an older
// version took in place of each: NetBox 3.7's device_role and content_types
// spellings, Nautobot 1.6's site, device_role, lowercase status slugs and
// assigned_object addressing. Each twin is a step that product's seedFor or
// webhookSteps defines.
var legacyTwin = map[string]map[string]string{
	"netbox": {"device": "device_v3", "custom_field": "custom_field_v3", "create_2": "create_2_v3"},
	"nautobot": {"device": "device_v1", "role": "role_v1", "location": "site_v1", "site": "site_v1",
		"mgmt": "mgmt_v1", "loopback": "loopback_v1", "mgmt_ip": "mgmt_ip_v1", "loop_ip": "loop_ip_v1",
		"create_2": "create_2_v1"},
}

// retryTwin names, per product, the step that retried a call the newest
// version itself refused as the brief first wrote it, spelled as that
// version's refusal asked: Nautobot 2.x takes an address only with its
// parent prefix or namespace. Both calls and both answers are in seed.json.
var retryTwin = map[string]map[string]string{
	"nautobot": {"mgmt_ip": "mgmt_ip_parent", "loop_ip": "loop_ip_parent"},
}

// lookup is the recorded value of "step.field", or the legacy twin's where
// -prefer-legacy is set and the twin succeeded, or the retry twin's where the
// step itself was refused.
func (r *recorder) lookup(ref string) (any, bool) {
	step, field, _ := strings.Cut(ref, ".")
	if r.legacy {
		if twin, ok := legacyTwin[r.product][step]; ok {
			if got, ok := r.ids[twin+"."+field]; ok {
				return got, true
			}
		}
	}
	if got, ok := r.ids[ref]; ok {
		return got, true
	}
	if twin, ok := retryTwin[r.product][step]; ok {
		got, ok := r.ids[twin+"."+field]
		return got, ok
	}
	return nil, false
}

var pathRef = regexp.MustCompile(`@[a-z0-9_]+\.[a-z]+`)

// expandPath replaces every @step.field in a path, as expand does in a body.
// A reference no step recorded is left as written, so the call goes out, is
// refused, and the refusal is recorded like any other answer.
func (r *recorder) expandPath(p string) string {
	return pathRef.ReplaceAllStringFunc(p, func(ref string) string {
		if got, ok := r.lookup(ref[1:]); ok {
			return fmt.Sprint(got)
		}
		return ref
	})
}

// expand replaces every string "@name.field" in v with the value field had in
// the response recorded as step name, so a later call can name an object an
// earlier one created. A reference no step recorded (its step was refused) is
// sent as null, and the call's own refusal is recorded.
func (r *recorder) expand(v any) any {
	switch t := v.(type) {
	case string:
		if len(t) > 1 && t[0] == '@' {
			if got, ok := r.lookup(t[1:]); ok {
				return got
			}
			return nil
		}
		return t
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = r.expand(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = r.expand(x)
		}
		return out
	}
	return v
}

// remember records a created object's id, name and url as "<step>.id",
// "<step>.name" and "<step>.url", when the call succeeded.
func (r *recorder) remember(x exchange) {
	if x.Status < 200 || x.Status > 299 {
		return
	}
	var obj map[string]any
	if json.Unmarshal(x.Body, &obj) == nil {
		for _, f := range []string{"id", "name", "url"} {
			if v, ok := obj[f]; ok {
				r.ids[x.Step+"."+f] = v
			}
		}
	}
}

func (r *recorder) write(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail("%s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(r.out, name), append(b, '\n'), 0o644); err != nil {
		fail("%s: %v", name, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "sot-record: "+format+"\n", args...)
	os.Exit(1)
}

// hook is one webhook delivery as it arrived.
type hook struct {
	At          time.Time         `json:"at"`
	Headers     map[string]string `json:"headers"`
	Body        json.RawMessage   `json:"body"`
	SignatureOK bool              `json:"signature_is_hmac_sha512_of_body"`
}

func main() {
	product := flag.String("product", "", "netbox or nautobot")
	base := flag.String("url", "", "the API base, e.g. http://127.0.0.1:18080")
	out := flag.String("out", "", "the fixture directory to write")
	listen := flag.String("webhook-listen", "", "host:port the product can reach this recorder on")
	legacy := flag.Bool("prefer-legacy", false, "name the objects an older version's spelling created")
	scheme := flag.String("auth-scheme", "Token", `the Authorization scheme: "Token", or "Bearer" for a NetBox v2 token`)
	wait := flag.Duration("webhook-wait", 20*time.Second, "how long to wait for the worker to deliver")
	probeV1 := flag.Bool("probe-v1-token", false, "NetBox 4: issue a v1 token over the API and try it with the Token scheme")
	depth1 := flag.Bool("depth1-read", false, "Nautobot 2: read the device again with ?depth=1")
	flag.Parse()
	token, secret := os.Getenv("L27_TOKEN"), os.Getenv("L27_WEBHOOK_SECRET")
	if *product == "" || *base == "" || *out == "" || *listen == "" || token == "" || secret == "" {
		fail("-product, -url, -out, -webhook-listen, L27_TOKEN and L27_WEBHOOK_SECRET are required")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail("%v", err)
	}
	r := &recorder{base: *base, token: token, scheme: *scheme, product: *product, out: *out, legacy: *legacy,
		client: &http.Client{Timeout: 60 * time.Second}, ids: map[string]any{}, secrets: credentialParts(token)}

	var mu sync.Mutex
	var hooks []hook
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail("webhook listener: %v", err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		mac := hmac.New(sha512.New, []byte(secret))
		mac.Write(body)
		h := hook{At: time.Now().UTC(), Headers: map[string]string{}, Body: body,
			SignatureOK: req.Header.Get("X-Hook-Signature") == hex.EncodeToString(mac.Sum(nil))}
		if !json.Valid(body) {
			h.Body, _ = json.Marshal(string(body))
		}
		for k, vs := range req.Header {
			h.Headers[k] = strings.Join(vs, ", ")
		}
		mu.Lock()
		hooks = append(hooks, h)
		mu.Unlock()
		fmt.Printf("sot-record: webhook delivery, signature verified %t\n", h.SignatureOK)
	}))

	r.write("status.json", r.call("status", "GET", "/api/status/", nil))
	r.write("api-root.json", r.call("api_root", "GET", "/api/", nil))
	if *probeV1 {
		// Whether NetBox 4 still takes a v1 token: issue one for the admin
		// (user 1, the only user) and read /api/status/ with "Token <it>".
		// The issued token is redacted from the fixture like the run's own.
		create, got := r.callAs("v1_token_create", "POST", "/api/users/tokens/",
			map[string]any{"user": 1, "version": 1, "description": "l27 v1 probe"}, r.scheme+" "+r.token, []string{"token", "key"})
		probe := []exchange{create}
		fmt.Printf("sot-record: v1_token_create: %d\n", create.Status)
		if tok := got["token"]; tok != "" {
			x, _ := r.callAs("v1_token_status", "GET", "/api/status/", nil, "Token "+tok, nil)
			probe = append(probe, x)
			fmt.Printf("sot-record: v1_token_status: %d\n", x.Status)
		}
		r.write("auth-v1.json", probe)
	}
	var seeded []exchange
	for _, s := range seedFor(*product, r) {
		x := r.call(s.step, s.method, s.path, s.body)
		r.remember(x)
		seeded = append(seeded, x)
		fmt.Printf("sot-record: seed %s %s %s: %d\n", s.step, s.method, x.Path, x.Status)
	}
	r.write("seed.json", seeded)
	r.write("rest-device.json", r.call("rest_device", "GET", "/api/dcim/devices/?name=leaf-01", nil))
	if *depth1 {
		r.write("rest-device-depth1.json", r.call("rest_device_depth1", "GET", "/api/dcim/devices/?name=leaf-01&depth=1", nil))
	}
	r.write("rest-page.json", r.call("rest_page", "GET", "/api/dcim/devices/?limit=1", nil))
	// NetBox serves GraphQL at /graphql/, Nautobot at /api/graphql/; a 404
	// here is recorded like any other answer.
	gqlPath := "/graphql/"
	if *product == "nautobot" {
		gqlPath = "/api/graphql/"
	}
	var gql []exchange
	for i, q := range graphQLCandidates(*product) {
		x := r.call(fmt.Sprintf("graphql_%d", i), "POST", gqlPath, map[string]any{"query": q})
		gql = append(gql, x)
		fmt.Printf("sot-record: graphql_%d: %d\n", i, x.Status)
	}
	r.write("graphql.json", gql)

	var hookCalls []exchange
	for _, s := range webhookSteps(*product, "http://"+*listen+"/", secret) {
		x := r.call(s.step, s.method, s.path, s.body)
		r.remember(x)
		hookCalls = append(hookCalls, x)
		fmt.Printf("sot-record: webhook step %s %s %s: %d\n", s.step, s.method, x.Path, x.Status)
	}
	time.Sleep(*wait) // the worker delivers asynchronously
	mu.Lock()
	for i := range hooks {
		hooks[i].Body = r.redact(hooks[i].Body)
		for k, v := range hooks[i].Headers {
			hooks[i].Headers[k] = string(r.redact([]byte(v)))
		}
	}
	r.write("webhooks.json", map[string]any{"calls": hookCalls, "deliveries": hooks})
	mu.Unlock()
	fmt.Printf("sot-record: %s at %s: %d seed calls, %d GraphQL candidates, %d webhook deliveries\n",
		*product, *base, len(seeded), len(gql), len(hooks))
}
