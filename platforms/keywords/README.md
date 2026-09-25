# Keyword trees

`<set version>/<platform>.yaml` is a projected platform's CLI keyword tree, as the lab captured it
on every image that set measures (spec §8; §15 L26). Junos matches `deny-commands` and
`allow-commands` against a command's keywords only, so the projection sends a rule only where
this tree proves each of its words a keyword. A released set's tree is never edited: a new
capture ships in a new set.
