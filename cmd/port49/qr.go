package main

import (
	"strings"

	"github.com/boombuler/barcode/qr"
)

// qrText draws s as a QR code for a terminal: two modules a character
// (the upper and lower half blocks), dark modules as blocks on the
// terminal's own background, with a quiet zone of four modules (ISO/IEC
// 18004). It is printed on the person's terminal alone (decision 47 ruling 15).
func qrText(s string) (string, error) {
	code, err := qr.Encode(s, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := code.Bounds().Dx()
	size := n + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		if x < 0 || y < 0 || x >= n || y >= n {
			return false
		}
		r, _, _, _ := code.At(x, y).RGBA()
		return r == 0
	}
	var b strings.Builder
	for y := 0; y < size; y += 2 {
		for x := 0; x < size; x++ {
			switch top, bottom := dark(x, y), dark(x, y+1); {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
