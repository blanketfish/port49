package lab

// L81 is an IP address as the TLS server name (spec §15 L81; decision 50
// ruling 10). Cell (a) runs on the lab host with reference clients; cell (b)
// needs a vJunos-router reaching port49 over IPv6, and is not run here.

// l81Listed is the address server_names lists, and l81ListedSpelling the
// same address as openssl sends it: another spelling, so a match is by
// address. l81Unlisted is an address server_names does not list, spelled
// the same uncanonical way, so the record's detail shows openssl sends the
// text it is given.
const (
	l81Listed         = "2001:db8::1"
	l81ListedSpelling = "2001:0DB8:0:0::1"
	l81Unlisted       = "2001:0DB8:0:0::2"
)

const l81ClaimA = "openssl s_client -servername <IPv6 literal> against a listener whose server_names lists it in " +
	"another spelling: accepted. An unlisted one is refused with the alert (best-effort, recorded) and " +
	"sni_mismatch, and the next connection inside the window is reset at Accept, with no strike and no second " +
	"record."

// l81Obs is what cell (a) saw, from port49's records and metrics.
type l81Obs struct {
	acceptedOK      float64 // the rise in port49_tls_handshakes_total{outcome="ok"} across the listed spelling's connection
	acceptedRecords int     // sni_mismatch records that connection made
	refused         int     // sni_mismatch records after the unlisted address's two connections
	refusedDetail   bool    // the record's detail names the spelling openssl sent
	declinedRise    float64 // the rise in declined_refused across the unlisted address's two connections
	heldRise        float64 // the rise in held_refused across them
}

// l81AgreesA is whether cell (a) agrees with decision 50 ruling 10.
func l81AgreesA(o l81Obs) bool {
	return o.acceptedOK == 1 && o.acceptedRecords == 0 && o.refused == 1 && o.refusedDetail &&
		o.declinedRise == 1 && o.heldRise == 0
}
