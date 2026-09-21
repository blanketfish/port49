package wire

const (
	HeaderLen  = 12
	MaxBodyLen = 4096 // port49's own ceiling; RFC 8907 sets none (spec §10, L10)

	MajorVersion     = 0xc
	MinorVersionZero = 0x0
	MinorVersionOne  = 0x1

	FlagUnencrypted   = 0x01
	FlagSingleConnect = 0x04
)

type Type uint8

const (
	TypeAuthen Type = 1
	TypeAuthor Type = 2
	TypeAcct   Type = 3
)

// Authentication.
const (
	AuthenActionLogin    = 0x01
	AuthenActionChPass   = 0x02
	AuthenActionSendAuth = 0x04

	AuthenTypeASCII    = 0x01
	AuthenTypePAP      = 0x02
	AuthenTypeCHAP     = 0x03
	AuthenTypeMSCHAP   = 0x05
	AuthenTypeMSCHAPv2 = 0x06

	AuthenServiceNone   = 0x00
	AuthenServiceLogin  = 0x01
	AuthenServiceEnable = 0x02
	AuthenServicePPP    = 0x03

	AuthenStatusPass    = 0x01
	AuthenStatusFail    = 0x02
	AuthenStatusGetData = 0x03
	AuthenStatusGetUser = 0x04
	AuthenStatusGetPass = 0x05
	AuthenStatusRestart = 0x06
	AuthenStatusError   = 0x07
	AuthenStatusFollow  = 0x21

	AuthenReplyFlagNoEcho   = 0x01
	AuthenContinueFlagAbort = 0x01
)

// Authorization.
const (
	AuthenMethodNotSet     = 0x00
	AuthenMethodNone       = 0x01
	AuthenMethodKRB5       = 0x02
	AuthenMethodLine       = 0x03
	AuthenMethodEnable     = 0x04
	AuthenMethodLocal      = 0x05
	AuthenMethodTACACSPlus = 0x06
	AuthenMethodGuest      = 0x08
	AuthenMethodRADIUS     = 0x10
	AuthenMethodKRB4       = 0x11
	AuthenMethodRCMD       = 0x20

	AuthorStatusPassAdd  = 0x01
	AuthorStatusPassRepl = 0x02
	AuthorStatusFail     = 0x10
	AuthorStatusError    = 0x11
	AuthorStatusFollow   = 0x21
)

// Accounting.
const (
	AcctFlagStart    = 0x02
	AcctFlagStop     = 0x04
	AcctFlagWatchdog = 0x08

	AcctStatusSuccess = 0x01
	AcctStatusError   = 0x02
	AcctStatusFollow  = 0x21
)
