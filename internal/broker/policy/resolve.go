package policy

// SubjectOf names the subject a principal resolves to, if any.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byIdentity[principal]
	return name, ok
}
