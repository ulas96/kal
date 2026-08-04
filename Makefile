# `set -a` exports what .env defines; plain `.` will not, and os.Getenv sees nothing.
ENV = set -a && . ./.env && set +a

.PHONY: help test test-db lint fmt vet cover audit check

help:
	@echo "test     go test ./...            (the TestDB* tests SKIP — see test-db)"
	@echo "test-db  same, with .env exported (the TestDB* tests run)"
	@echo "lint     golangci-lint run"
	@echo "fmt      gofmt -w ."
	@echo "vet      go vet ./..."
	@echo "cover    coverage profile + summary"
	@echo "audit    govulncheck + gosec"
	@echo "check    fmt check + vet + lint + test-db + audit"

test:
	go test ./...

# The only run that proves anything: the TestDB* tests skip silently without DATABASE_URL, and a
# skipped test still reports ok. In this library that silence would cover session revocation,
# token single-use and the unique index — the things a green run is assumed to have proven.
# -v so you can see that they ran.
test-db:
	$(ENV) && go test -v -count=1 ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

vet:
	go vet ./...

cover:
	$(ENV) && go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

# An auth library that does not scan its own dependency graph is asking every consumer to do it
# instead (luima's security review calls the missing gate B-01). Pinned to @latest deliberately:
# a vulnerability scanner frozen at an old version stops knowing about new vulnerabilities.
#
# govulncheck also reports standard-library vulnerabilities against the toolchain that built the
# code, so this fails on an out-of-date local Go even when kal and its dependencies are clean.
# That is the tool working: upgrade Go rather than suppressing it.
audit:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@$(MAKE) vet
	@$(MAKE) lint
	@$(MAKE) test-db
	@$(MAKE) audit
