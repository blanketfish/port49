//go:build lab

package lab

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
	"github.com/rhwendt/port49/tests/lab/labpcap"
)

// authenPkt is one AUTHEN packet of a test capture: the device's request at
// seq, or port49d's reply carrying status.
func authenPkt(at time.Time, port uint16, seq uint8, fromDevice bool, status string) wirePacket {
	p := wirePacket{Packet: labpcap.Packet{SrcPort: port, FromDevice: fromDevice,
		Header: wire.Header{Type: wire.TypeAuthen, SessionID: uint32(port), SeqNo: seq}, At: at}}
	if !fromDevice {
		p.decoded = "status=" + status
	}
	return p
}

// A step-3 token login that meets decision 37's dark is graded on what
// port49d answered before it: a verdict ERROR within packet_deadline is the
// hung store measured, whatever the device's later tries met; no ERROR, or
// one too late, is port49d's failure; a dark that came before port49d owed
// an answer leaves the cell unmeasured.
func TestHungLoginBeforeDark(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 17, 0, 0, 0, time.UTC)
	ms := func(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }
	dark := ms(5000)
	cases := []struct {
		name   string
		pkts   []wirePacket
		darkAt time.Time
		want   cellGrade
	}{
		{"Junos: GETPASS, then ERROR in 501ms, the second try after dark", []wirePacket{
			authenPkt(ms(100), 40001, 1, true, ""), authenPkt(ms(100), 40001, 2, false, "GETPASS(5)"),
			authenPkt(ms(200), 40001, 3, true, ""), authenPkt(ms(701), 40001, 4, false, "ERROR(7)"),
		}, dark, cellValid},
		{"NX-OS: ERROR on seq 1 in 501ms", []wirePacket{
			authenPkt(ms(3000), 40002, 1, true, ""), authenPkt(ms(3501), 40002, 2, false, "ERROR(7)"),
		}, dark, cellValid},
		{"answered ERROR, dark first seen a poll later", []wirePacket{
			authenPkt(ms(4600), 40003, 1, true, ""), authenPkt(ms(5100), 40003, 2, false, "ERROR(7)"),
		}, dark, cellValid},
		{"the verdict past packet_deadline", []wirePacket{
			authenPkt(ms(100), 40004, 1, true, ""), authenPkt(ms(2200), 40004, 2, false, "ERROR(7)"),
		}, dark, cellFailed},
		{"the verdict PASS", []wirePacket{
			authenPkt(ms(100), 40005, 1, true, ""), authenPkt(ms(600), 40005, 2, false, "PASS(1)"),
		}, dark, cellFailed},
		{"port49d held the request until dark", []wirePacket{
			authenPkt(ms(1000), 40006, 1, true, ""),
		}, dark, cellFailed},
		{"held after GETPASS until dark", []wirePacket{
			authenPkt(ms(100), 40007, 1, true, ""), authenPkt(ms(100), 40007, 2, false, "GETPASS(5)"),
			authenPkt(ms(200), 40007, 3, true, ""),
		}, dark, cellFailed},
		{"dark reset the request inside packet_deadline", []wirePacket{
			authenPkt(ms(4000), 40008, 1, true, ""),
		}, dark, cellInvalid},
		{"the device asked nothing before dark", nil, dark, cellInvalid},
		{"only a GETPASS before dark", []wirePacket{
			authenPkt(ms(4500), 40009, 1, true, ""), authenPkt(ms(4500), 40009, 2, false, "GETPASS(5)"),
		}, dark, cellInvalid},
		{"no dark time read", []wirePacket{
			authenPkt(ms(1000), 40010, 1, true, ""),
		}, time.Time{}, cellInvalid},
		{"held 2.1s, inside packet_deadline and the poll's slack", []wirePacket{
			authenPkt(ms(2900), 40017, 1, true, ""),
		}, dark, cellInvalid},
		{"held 2.3s, past packet_deadline and the poll's slack", []wirePacket{
			authenPkt(ms(2700), 40018, 1, true, ""),
		}, dark, cellFailed},
		{"a later try held 3.5s until dark", []wirePacket{
			authenPkt(ms(100), 40011, 1, true, ""), authenPkt(ms(601), 40011, 2, false, "ERROR(7)"),
			authenPkt(ms(1500), 40012, 1, true, ""),
		}, dark, cellFailed},
		{"a later try answered PASS", []wirePacket{
			authenPkt(ms(100), 40013, 1, true, ""), authenPkt(ms(601), 40013, 2, false, "ERROR(7)"),
			authenPkt(ms(1100), 40014, 1, true, ""), authenPkt(ms(1600), 40014, 2, false, "PASS(1)"),
		}, dark, cellFailed},
		{"a later try cut off by dark inside packet_deadline", []wirePacket{
			authenPkt(ms(100), 40015, 1, true, ""), authenPkt(ms(601), 40015, 2, false, "ERROR(7)"),
			authenPkt(ms(4000), 40016, 1, true, ""),
		}, dark, cellValid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := hungLoginBeforeDark(exchangesIn(c.pkts, t0, ms(60000)), c.darkAt, 2*time.Second)
			if got != c.want {
				t.Errorf("graded %v (%s), want %v", got, why, c.want)
			}
			if why == "" {
				t.Error("no reason given")
			}
		})
	}
}

// exchangesIn pairs each device request in the window with the reply on its
// connection and session at the next seq, and leaves out requests outside it.
// Sessions differ from ports, so the port and the session are each checked
// on their own.
func TestExchangesIn(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 17, 0, 0, 0, time.UTC)
	at := func(ms int) time.Time { return t0.Add(time.Duration(ms) * time.Millisecond) }
	pkt := func(ms int, port uint16, session uint32, seq uint8, fromDevice bool, status string) wirePacket {
		p := authenPkt(at(ms), port, seq, fromDevice, status)
		p.Header.SessionID = session
		return p
	}
	pkts := []wirePacket{
		pkt(-1000, 1, 101, 1, true, ""), pkt(-1000, 1, 101, 2, false, "ERROR(7)"), // before the window
		pkt(1000, 2, 102, 1, true, ""), pkt(1500, 3, 102, 2, false, "PASS(1)"), // same session, another port
		pkt(2000, 4, 104, 1, true, ""), pkt(2200, 4, 999, 2, false, "PASS(1)"), // same port, another session
		pkt(3000, 5, 105, 1, true, ""), pkt(3500, 5, 105, 2, false, "ERROR(7)"),
	}
	xs := exchangesIn(pkts, t0, t0.Add(time.Minute))
	if len(xs) != 3 {
		t.Fatalf("got %d exchanges, want 3: %+v", len(xs), xs)
	}
	if xs[0].Reply != nil {
		t.Errorf("a reply on another connection, same session, was paired: %+v", xs[0].Reply)
	}
	if xs[1].Reply != nil {
		t.Errorf("a reply in another session, same connection, was paired: %+v", xs[1].Reply)
	}
	if xs[2].Reply == nil || replyStatus(*xs[2].Reply) != "ERROR(7)" {
		t.Errorf("the matching request's reply: %+v", xs[2].Reply)
	}
}
