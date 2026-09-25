package policy

import "github.com/rhwendt/port49/internal/platform"

// setKeywords is a set's keyword tree for a platform (platform.KeywordsFor):
// the projection sends a rule only where it proves the rule's words keywords
// (spec §13 decision 27). It is the pinned set's measurement, never a
// `platforms:` block's, and tests replace it to stand up a set of their own.
var setKeywords = platform.KeywordsFor
