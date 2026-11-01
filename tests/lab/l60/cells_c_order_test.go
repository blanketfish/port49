//go:build hwkey && hwkey_dlopen

package l60

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/clientkey"
	"github.com/blanketfish/port49/internal/hwkey/pkcs11"
	"github.com/blanketfish/port49/internal/mfatouch"
)

// f9Label is libykcs11's label of the device attestation certificate.
const f9Label = "X.509 Certificate for PIV Attestation"

// The (c) sub-cell on certificate order, with slot 9a holding its imported
// lab certificate beside its attestation. Read-only: one session, opened by
// port49's own opener on slot 9a's key, with no login, no PIN, no signing,
// and nothing written. It needs no terminal.
//
//  1. Every certificate object, in the order C_FindObjects returns it.
//  2. What port49 picks for slot 9a's client certificate (Certificate(), as
//     `port49 login --key` with no --cert does), and Certificates().
//  3. Whether mfatouch.Chain picks the same chain from the objects in their
//     order and reversed.
func TestL60COrder(t *testing.T) {
	gate(t, gateCOrder, "read-only: the certificate objects' order; no PIN, no terminal")
	h := setupLab(t, "c_order", false, nil, io.Discard, labDir(t))
	h.needPKCS11()

	k, err := clientkey.Open(h.keyRef(slot9a, false), nil)
	if err != nil {
		t.Fatalf("opening slot 9a with no PIN: %s", redact(err.Error()))
	}
	defer k.Close()
	s, ok := k.(*pkcs11.Signer)
	if !ok {
		t.Fatalf("slot 9a opened as %T, not a PKCS#11 key", k)
	}
	h.obs("session", "one read-only session on slot 9a's token, no login; key state "+k.State().String())

	// 1. The objects in their order.
	objs, err := pkcs11.CertificateObjects(s)
	if err != nil {
		t.Fatalf("listing the certificate objects: %s", redact(err.Error()))
	}
	h.obs("object_count", strconv.Itoa(len(objs)))
	type listed struct {
		id    []byte
		label string
		cert  *x509.Certificate
	}
	var certs []listed
	var f9 *x509.Certificate
	for _, o := range objs {
		if o.Err != nil {
			certs = append(certs, listed{o.ID, string(o.Label), nil})
			continue
		}
		c, err := x509.ParseCertificate(o.DER)
		if err != nil {
			certs = append(certs, listed{o.ID, string(o.Label), nil})
			continue
		}
		certs = append(certs, listed{o.ID, string(o.Label), c})
		if string(o.Label) == f9Label {
			f9 = c
		}
	}
	if f9 == nil {
		h.obs("f9", "no object labelled "+strconv.Quote(f9Label))
	}
	isAtt := func(c *x509.Certificate) bool {
		return f9 != nil && c != nil && c != f9 && bytes.Equal(c.RawIssuer, f9.RawSubject)
	}
	for i, l := range certs {
		v := fmt.Sprintf("cka_id=%s cka_label=%q", hex.EncodeToString(l.id), l.label)
		if l.cert == nil {
			v += " value unreadable or not a certificate"
		} else {
			v += fmt.Sprintf(" subject_cn=%q issuer_cn=%q attestation=%v", l.cert.Subject.CommonName,
				l.cert.Issuer.CommonName, isAtt(l.cert))
		}
		h.obs("object_"+strconv.Itoa(i), v)
	}

	// 2. What port49 picks for the client certificate.
	lab := labCertDER(h.dir)
	describe := func(c *x509.Certificate) string {
		what := "neither the lab certificate nor an attestation"
		switch {
		case lab != nil && bytes.Equal(c.Raw, lab):
			what = "the lab certificate (slot9a.pem)"
		case isAtt(c):
			what = "an ATTESTATION"
		case c == f9 || (f9 != nil && bytes.Equal(c.Raw, f9.Raw)):
			what = "the f9 certificate"
		}
		return fmt.Sprintf("subject_cn=%q issuer_cn=%q: %s", c.Subject.CommonName, c.Issuer.CommonName, what)
	}
	leaf, err := s.Certificate()
	if err != nil {
		h.obs("certificate", "error: "+err.Error())
	} else {
		h.obs("certificate", describe(leaf))
		pub, _ := k.Public().(interface{ Equal(crypto.PublicKey) bool })
		h.obs("certificate_key_is_slot9a_key", strconv.FormatBool(pub != nil && pub.Equal(leaf.PublicKey)))
	}
	list, err := s.Certificates()
	if err != nil {
		t.Fatalf("Certificates(): %v", err)
	}
	var cns []string
	for _, c := range list {
		cns = append(cns, strconv.Quote(c.Subject.CommonName))
	}
	h.obs("certificates", fmt.Sprintf("%d, in order: %s", len(list), strings.Join(cns, ", ")))

	// 3. The touch proof's chain, in order and reversed. The touch key here is
	// slot 9c's, read from its attestation (CKA_ID 02): no second session.
	var pub9c crypto.PublicKey
	for _, l := range certs {
		if hex.EncodeToString(l.id) == slot9c && isAtt(l.cert) {
			pub9c = l.cert.PublicKey
		}
	}
	if pub9c == nil {
		h.obs("chain", "no slot 9c attestation listed; the chain is not built")
		return
	}
	rev := slices.Clone(list)
	slices.Reverse(rev)
	pub9a := k.Public()
	for _, roles := range []struct {
		name           string
		touch, session crypto.PublicKey
	}{{"touch_9c_session_9a", pub9c, pub9a}, {"touch_9a_session_9c", pub9a, pub9c}} {
		fwd, errF := mfatouch.Chain(list, roles.touch, roles.session)
		back, errB := mfatouch.Chain(rev, roles.touch, roles.session)
		h.obs("chain_"+roles.name+"_listed_order", chainWords(fwd, errF, describe))
		h.obs("chain_"+roles.name+"_reversed", chainWords(back, errB, describe))
		h.obs("chain_"+roles.name+"_same", strconv.FormatBool(errF == nil && errB == nil && slices.Equal(fwd, back)))
	}
}
