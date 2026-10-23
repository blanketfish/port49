package platform

// tlsServerSingleConnect is every shipped platform port49 offers
// single-connect to on the RFC 9887 listener, each with the lab note that
// measured why (spec §13 decision 50 ruling 20). It is a built-in wire fact,
// never configured: a wrong entry is a fault the operator has nothing to
// measure with. A firmware whose profile says otherwise fails tests/qual's
// drift test, not production.
//
//   - cisco_nxos: NX-OS 10.6(2)F over per-request TLS writes the next
//     request about 20 ms after an accounting record, on the same
//     connection, without reading the reply. Closed after one session, the
//     connection loses it, and with `none` as the device's fallback the
//     command runs unasked. Offered single-connect, it kept one connection
//     and asked about every command (the Task 7 A/B: 22 of 22 asked, 0
//     server-dead lines); tests/lab/results/L80-cisco_nxos.md.
var tlsServerSingleConnect = map[string]string{
	"cisco_nxos": "tests/lab/results/L80-cisco_nxos.md",
}

// TLSServerSingleConnect reports whether port49 sets the single-connect flag
// in its first reply on the RFC 9887 listener to a device of wirePlatform,
// the shipped platform whose wire facts the device is read by: its own, or
// its `based_on:` base (spec §8).
func TLSServerSingleConnect(wirePlatform string) bool {
	_, ok := tlsServerSingleConnect[wirePlatform]
	return ok
}

// TLSServerSingleConnectPlatforms lists the table's platforms, sorted:
// tests/qual's drift test holds each to a profile that measured it honored.
func TLSServerSingleConnectPlatforms() []string {
	return sortedKeys(tlsServerSingleConnect)
}
