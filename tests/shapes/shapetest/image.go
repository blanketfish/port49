package shapetest

// DebianTrixieSlim is the one Debian base image the systemd smoke's Dockerfile and the client package's
// import test run in, by digest: a bump is an edit here, and a test requires the Dockerfile's FROM line to
// match it.
const DebianTrixieSlim = "debian:trixie-slim@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31"
