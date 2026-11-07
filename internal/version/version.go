// Package version holds the version every port49 binary reports. The Makefile and the release
// set it at link time with -ldflags "-X github.com/blanketfish/port49/internal/version.Version=...";
// an unstamped build says dev.
package version

// Version is the build's version, stamped at link time.
var Version = "dev"

// Line is what `<binary> --version` prints, without the newline.
func Line(binary string) string { return binary + " " + Version }
