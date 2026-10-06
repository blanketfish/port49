// Package oidc reads OpenID Connect tokens for the broker (plan 7h; spec §13
// decision 39): a compact JWS verified on the standard library's
// cryptography, keys from one issuer's JWKS refreshed and aged out, an ID
// token or a client-credentials access token turned into a principal in the
// trust domain of the one verifier that accepts it, and a back-channel
// logout token validated per OpenID Connect Back-Channel Logout 1.0.
//
// What it never does: read a group, a role or a username from a token (the
// directory gives those, design §7); follow a key a token's header names
// (jku, jwk, x5u, x5c); accept none or an HMAC; or say anything a token
// that did not verify claims, its iss and kid included, since an
// unvalidated body is never logged. The daemon never imports it: it never
// sees a token.
package oidc
