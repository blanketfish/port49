// Package directory is port49's one door to LDAP and Active Directory
// (design §10; plan 7g): the server pool, the bind, the
// certificate-to-directory mapping, nested group membership, the
// membership kept in the store, grace and pre-warm.
//
// Only the broker imports it. port49d never speaks to a directory: a
// directory outage reaches a live session through the staleness ceiling
// alone (design §9). Nothing here reads a group from a credential, writes
// to a directory, or binds as a user.
//
// Nothing here formats a bind password, a keytab's bytes or a Kerberos
// ticket into a line, a record or an error.
package directory
