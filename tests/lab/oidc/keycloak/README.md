# Keycloak realm for the identity-provider lab

`realm.json` holds the lab's own secrets (`lab-only-alice-password`, `lab-only-svc-secret`),
published with the repository for a realm that lives one run on one host's loopback.
Each test replaces `port49-cli`'s `backchannel.logout.url` (`SetLogoutURL`), so the
`receiver.invalid` value here is never delivered to.
