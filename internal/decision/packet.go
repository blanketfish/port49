package decision

import (
	"fmt"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// PacketFields is a validated request's header fields, as names (spec §5.7;
// §13 decision 52 ruling 3). Never a user, a port, an address, data or an
// argument.
type PacketFields struct {
	Action       string `json:"action,omitempty"` // authentication only
	AuthenType   string `json:"authen_type"`
	Service      string `json:"service"`
	AuthenMethod string `json:"authen_method,omitempty"` // authorization and accounting only
	PrivLvl      uint8  `json:"priv_lvl"`
}

// named maps a header value to its name. A value outside the list is
// unknown_<n>: the header byte, which is not free-form wire text.
func named(m map[uint8]string, v uint8) string {
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprintf("unknown_%d", v)
}

var (
	actions  = map[uint8]string{wire.AuthenActionLogin: "login", wire.AuthenActionChPass: "chpass", wire.AuthenActionSendAuth: "sendauth"}
	types    = map[uint8]string{0: "not_set", wire.AuthenTypeASCII: "ascii", wire.AuthenTypePAP: "pap", wire.AuthenTypeCHAP: "chap", wire.AuthenTypeMSCHAP: "mschap", wire.AuthenTypeMSCHAPv2: "mschapv2"}
	services = map[uint8]string{wire.AuthenServiceNone: "none", wire.AuthenServiceLogin: "login", wire.AuthenServiceEnable: "enable", wire.AuthenServicePPP: "ppp", 5: "pt", 6: "rcmd", 7: "x25", 8: "nasi", 9: "fwproxy"}
	methods  = map[uint8]string{wire.AuthenMethodNotSet: "not_set", wire.AuthenMethodNone: "none", wire.AuthenMethodKRB5: "krb5", wire.AuthenMethodLine: "line", wire.AuthenMethodEnable: "enable", wire.AuthenMethodLocal: "local", wire.AuthenMethodTACACSPlus: "tacacsplus", wire.AuthenMethodGuest: "guest", wire.AuthenMethodRADIUS: "radius", wire.AuthenMethodKRB4: "krb4", wire.AuthenMethodRCMD: "rcmd"}
)

func AuthenFields(s wire.AuthenStart) *PacketFields {
	return &PacketFields{Action: named(actions, s.Action), AuthenType: named(types, s.AuthenType),
		Service: named(services, s.Service), PrivLvl: s.PrivLvl}
}

func AuthorFields(r wire.AuthorRequest) *PacketFields {
	return &PacketFields{AuthenType: named(types, r.AuthenType), Service: named(services, r.Service),
		AuthenMethod: named(methods, r.AuthenMethod), PrivLvl: r.PrivLvl}
}

func AcctFields(r wire.AcctRequest) *PacketFields {
	return &PacketFields{AuthenType: named(types, r.AuthenType), Service: named(services, r.Service),
		AuthenMethod: named(methods, r.AuthenMethod), PrivLvl: r.PrivLvl}
}
