package ci

// Task 23: the Contributing pages. Each string is a fact a contributor needs from the page.
func init() {
	mustSay["contributing/index.md"] = append(mustSay["contributing/index.md"],
		"make hooks", "make test && make vet", "closed — measured", "A results note wins over a doc",
	)
	mustSay["contributing/qualification.md"] = append(mustSay["contributing/qualification.md"],
		"make qual-vet", "engine_gaps", "-only=", "never hosted", "--8<-- \"tests/lab/README.md:regressions\"",
	)
	mustSay["contributing/releasing.md"] = append(mustSay["contributing/releasing.md"],
		"--8<-- \"RELEASING.md:release\"", "Only a maintainer cuts a release",
	)
}
