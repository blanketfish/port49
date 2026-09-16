.PHONY: test vet fuzz lab build

build:
	go build -o bin/port49d ./cmd/port49d

test:
	go test ./... -count=1

vet:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

# Short fuzz pass for every FuzzXxx in the wire package; CI-sized.
fuzz:
	@for f in $$(go test -list 'Fuzz.*' ./internal/tacacs/wire | grep '^Fuzz'); do \
	  go test ./internal/tacacs/wire -run '^$$' -fuzz "^$$f$$" -fuzztime 20s || exit 1; \
	done

# Requires containerlab and device images; see tests/lab/README.md.
lab:
	go test -tags lab ./tests/lab/... -count=1 -v -timeout 30m
