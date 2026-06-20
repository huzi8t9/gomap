# Contributing to gomap

Thanks for considering a contribution. This is a small Go network scanner -- keep changes focused and dependency-free where possible.

## Setup

```
go build -o gomap .
go vet ./...
```

No test suite yet. If you add one, use the standard `go test ./...`.

## Code style

- Standard `gofmt`/`go vet` clean before committing.
- No comments explaining *what* code does — name things clearly instead.
  Comments are for non-obvious *why* (a workaround, a protocol quirk, a platform constraint).
- Keep the dependency list minimal (currently just `golang.org/x/net` for ICMP). Don't add a library for something the stdlib already covers.
- Platform-specific code (e.g. raw sockets) goes in `_linux.go` / `_other.go` files with build tags, not runtime OS checks.

## Branches & commits

- Branch off `main`, name branches `feature/<short-name>` or `fix/<short-name>`.
- Commit messages: short imperative subject line, body explains *why* if it's not obvious from the diff.

## Pull requests

- One logical change per PR. Don't bundle unrelated fixes.
- Describe what changed and why in the PR description.
- Make sure `go build` and `go vet` pass before opening the PR.

## Scope of changes

This tool sends raw packets and probes hosts/ports. Before adding a new
scan technique or probe, briefly note in the PR what it does on the wire
(e.g. "sends X to port Y, reads response for Z") so reviewers can reason
about its network behavior.

## Responsible use

This is a network scanning tool. Only scan hosts/networks you own or have
explicit authorisation to test. Don't submit features whose primary purpose
is evading detection or enabling unauthorised access.

## Reporting bugs / security issues

Open a GitHub issue with repro steps (target environment, command run,
expected vs actual). For anything you believe is a security
vulnerability in gomap itself, open an issue marked clearly as security so
it can be triaged first.
