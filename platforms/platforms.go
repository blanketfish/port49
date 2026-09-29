// Package platforms holds the built-in platform adapters as the files they are
// (spec §8, "Knowing what is shipped"): one directory per platform set, named
// by its version, one YAML file per platform in it. They are embedded in both
// binaries, and they are browsable and diffable across tags without running
// anything. internal/platform parses them; nothing else reads this package.
//
// A set, once released, is never edited: a policy pins one (`platform_set:`),
// and a binary upgrade must not change what a pinned policy renders (spec §8,
// "the platform set is pinned"). A change to a shipped adapter is a new
// directory.
package platforms

import "embed"

// FS is every built-in set: `<version>/<platform>.yaml`.
//
//go:embed */*.yaml
var FS embed.FS

// Redact is the built-in redaction table (spec §5.8), which is not pinned:
// redaction changes what the log keeps, never what anyone may do.
//
//go:embed redact.yaml
var Redact []byte

// Keywords is every set's CLI keyword trees: `keywords/<version>/<platform>.yaml`
// (internal/platform.KeywordsFor). They sit outside the set directories, which
// hold one adapter file per platform and nothing else.
//
//go:embed keywords
var Keywords embed.FS
