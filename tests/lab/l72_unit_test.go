package lab

import (
	"strings"
	"testing"
)

// Every L72 cell named in spec §15 has a runner, and none is run twice.
func TestL72CellsAreTheRegistersCells(t *testing.T) {
	want := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o"}
	got := map[string]bool{}
	for _, c := range l72Cells {
		if got[c.id] {
			t.Fatalf("cell %s twice", c.id)
		}
		got[c.id] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("cell %s has no runner", id)
		}
	}
}

func TestL72ParsesTheClientsLine(t *testing.T) {
	r, err := parseL72Result([]byte(`{"conn":1,"handshake":"error","error":"remote error: tls: bad certificate","resumed":false,"status":"none","flags":0,"after":"","closed_ms":0}` + "\n"))
	if err != nil || len(r) != 1 || r[0].Error != "remote error: tls: bad certificate" {
		t.Fatalf("%+v %v", r, err)
	}
}

// A made-up s_client transcript: every secret-bearing line goes, the alert
// and early-data lines stay.
const l72SampleTranscript = `CONNECTED(00000003)
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
    Session-ID-ctx: 
    Resumption PSK: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
    PSK identity: None
    PSK identity hint: None
    Master-Key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    TLS session ticket lifetime hint: 600 (seconds)
    TLS session ticket:
    0000 - 01 02 03 04 05 06 07 08-09 0a 0b 0c 0d 0e 0f 10   ................
    0010 - 11 12 13 14 15 16 17 18-19 1a 1b 1c 1d 1e 1f 20   ............... 

    Start Time: 1700000000
Reused, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
140000000:error:0A000416:SSL routines:ssl3_read_bytes:tlsv13 alert certificate required:../ssl/record/rec_layer_s3.c:1586:SSL alert number 116
Early data was not sent
`

func TestL72FilterDropsSessionSecrets(t *testing.T) {
	if len(l72TranscriptLeaks(l72SampleTranscript)) == 0 {
		t.Fatal("the sample carries secrets and the leak check missed them")
	}
	got := l72FilterTranscript(l72SampleTranscript)
	if hits := l72TranscriptLeaks(got); len(hits) > 0 {
		t.Fatalf("still carries %v:\n%s", hits, got)
	}
	for _, s := range []string{"00112233445566778899", "aabbccddeeff", "0123456789abcdef", "01 02 03 04"} {
		if strings.Contains(got, s) {
			t.Errorf("the filtered transcript still holds %q", s)
		}
	}
	for _, keep := range []string{"alert number 116", "Early data was not sent", "Reused, TLSv1.3", "Protocol  : TLSv1.3"} {
		if !strings.Contains(got, keep) {
			t.Errorf("the filter dropped %q", keep)
		}
	}
}
