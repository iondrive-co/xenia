# Signing providers

Xenia can delegate a signing scheme to an explicitly configured executable.
The executable can use any language or its own dependency environment. Xenia
handles credential access, approvals, profile selection and audit records.
The provider validates its input against the installed profile and produces
the signature.

## Register a provider

Add a scheme to `signing_providers` in `~/.config/xenia/config.json`, or the
file selected by `XENIA_CONFIG`:

```json
{
  "signing_providers": {
    "example-signing": {
      "command": ["/usr/local/libexec/request-signer"],
      "timeout_s": 15
    }
  }
}
```

`command` is an argument list, executed directly without a shell. Its first
argument must be an absolute executable path. The working directory is `/`;
use absolute paths for script arguments too. `timeout_s` defaults to 15 and
must be greater than zero and at most 120 seconds.

Use an approved installation of the provider, with its executable, scripts,
dependencies and configuration protected from changes by callers. The
provider receives the credential and is trusted with it. Process separation
lets providers manage their dependencies; it does not sandbox their access
to the credential.

Restart the service after changing provider registration. Register the same
configuration for the command and service. `xenia secret schemes` and the
broker's `ops` response include configured providers. Availability means the
command is configured correctly and its executable exists and can run; the
provider can still refuse a request if a dependency is missing.

Built-in scheme names take precedence over provider registrations.

## Install a profile

An installed credential profile selects the scheme and contains the
provider's settings. For example, supply this JSON to
`xenia secret sign service-key submit` on standard input:

```json
{
  "scheme": "example-signing",
  "action": "submit",
  "limits": {"amount": 10}
}
```

The provider defines and enforces the meaning of `action` and `limits`.
Callers select an approved profile by name. A profile or request cannot
register an executable. Existing grants, including profile-scoped standing
approvals, apply to provider signing.

## Protocol 1

Each invocation receives one UTF-8 JSON object on standard input, followed
by a newline and EOF. The credential is passed only in that input, never in
command arguments. The request contains:

```json
{
  "protocol": 1,
  "secret": "example-value",
  "method": "POST",
  "url": "https://api.example.test/submit",
  "headers": {"Content-Type": "application/json"},
  "body": "{\"amount\":7}",
  "config": {
    "scheme": "example-signing",
    "action": "submit",
    "limits": {"amount": 10}
  },
  "nonce": 12,
  "now": 1600000000.0,
  "extras": {}
}
```

`body` is the exact input string, including when it contains JSON. `config`
is the installed profile and may include internal fields such as `_method`.
`nonce` is allocated by Xenia; `now` is Unix time in seconds. `extras` holds
additional credential metadata provided by the profile. For a standalone
signing request, `method` is `SIGN` and `url` is empty.

After validating the request, write one JSON response to standard output
and exit successfully:

```json
{
  "protocol": 1,
  "signature": "example-signature",
  "headers": {"X-Request-Nonce": "12"}
}
```

`signature` must be a nonempty string. `headers` is optional and contains
additional string-valued HTTP headers. Header names must be HTTP tokens;
values cannot contain carriage returns or newlines. Xenia places signatures
through the existing `{{sign}}` or `{{sign:profile}}` mechanism, or returns
them for standalone signing. Standalone signing also returns the headers.

To refuse, return this response and exit successfully:

```json
{
  "protocol": 1,
  "refused": "amount exceeds the configured limit",
  "code": "off-policy"
}
```

`code` is `off-policy` by default; use `unavailable` when the provider cannot
perform the operation. A response must contain either a signature or a
refusal, with only the fields shown for that response type. Providers must
return request-specific signatures and public headers, and must never echo
credentials in successful output.

Standard output is limited to 1 MiB while being read. Standard error is
discarded. Invalid responses, unsuccessful exits, timeouts and communication
errors refuse with `unavailable`. Xenia terminates the invocation's process
group when it finishes or fails. Provider refusal reasons pass through the
broker's credential scrubber before being returned or recorded.

## Protocol 2: resident providers

Starting a process for every signature costs the provider's whole
startup, which for an interpreter with its libraries can be hundreds of
milliseconds. A provider registered with `"resident": true` is started
once and kept running, and each signature costs one exchange over its
pipes:

```json
{
  "signing_providers": {
    "example-signing": {
      "command": ["/usr/local/libexec/request-signer", "--resident"],
      "resident": true,
      "workers": 1,
      "timeout_s": 15,
      "request_timeout_s": 5
    }
  }
}
```

The service starts every resident provider when it starts, so the first
signature does not wait for one. `timeout_s` bounds a start and
`request_timeout_s` bounds one request; `workers` (1 to 16) is how many
copies serve requests side by side. Schemes registered with identical
settings share the same processes, so one provider can serve several
schemes.

After loading whatever it needs, the provider writes one line to
standard output:

```json
{"protocol": 2, "ready": true}
```

The scheme counts as available only after that line. Each request is
then one line on standard input: the protocol 1 request with
`"protocol": 2` and an integer `id`. The provider answers each request
with one line, carrying the same `id`:

```json
{"protocol": 2, "id": 7, "signature": "example-signature", "headers": {}}
```

or a refusal:

```json
{"protocol": 2, "id": 7, "refused": "amount exceeds the configured limit", "code": "off-policy"}
```

The fields and rules of protocol 1 apply to both. A worker gets one
request at a time. The provider exits when its standard input closes.

A request that runs past its deadline, a malformed reply, a reply with
another `id`, or an exit while a request is in flight refuses that
request with `unavailable`, and Xenia kills the worker's process group.
The worker starts again when the next request finds it stopped, after a
pause that doubles with each consecutive failure, from one second up to
thirty; requests made during the pause are refused with `unavailable`. A
refusal from the provider is an answer, not a failure: it does not stop
the worker. A worker that exits between requests is started again for
the next one.

The broker's `ops` response reports each resident provider's running
workers, pids, requests served, faults and recent latency.

## Pinning a provider

A provider may be pinned to the files it runs from:

```json
"files": ["/usr/local/libexec/request-signer"],
"sha256": "…"
```

`files` lists absolute paths, which may be directories. Before each
start (every invocation for protocol 1), Xenia hashes them and refuses
with `unavailable` if the result differs from `sha256`, so a changed
provider does not sign until its new hash is registered.

Every regular file under the pinned paths counts, including bytecode
caches such as `__pycache__` and `.pyc` files, because an interpreter
may run them in place of the source. A link counts as both where it
resolves to and what is there, and a linked directory is walked like any
other, once. A missing link target, a device, a socket or a pipe makes
the provider unavailable. `xenia secret digest PATH…` prints the hash for
a set of paths.

A provider therefore must not write under its own pinned paths, or its
next start is refused. For Python, run it with `-I -B` and either ship no
bytecode or compile it before pinning. The hash is taken before each
start: a process that can write the pinned files can still change them
between that check and the provider reading them, so a provider is best
installed where the users it signs for cannot write.

## Holding a value

By default the broker reads a credential's value from the credential store
on every use. A standing approval can instead hold it:

```
xenia grant NAME --host '(sign)' --until 2026-12-08 --profiles 'job-*' --reason 'why' --hold
```

The value is then kept in the broker's memory from the approval's first
use until the approval ends or is revoked, or until the credential's
policy row changes (adding the credential again counts). The approval is
still checked on every use, so a revoke stops the next request at once.
A sweep every `XENIA_HELD_SWEEP_S` seconds (30 by default) drops values
whose approval has ended, and stopping the service drops them all. While
a value is held, locking the credential store no longer stops it from
being used. Only standing approvals can hold. The `ops` response lists
held credentials by name under `held`, and `xenia grants` marks their
approvals.

Signing profiles are parsed once per change to the credential's row and
then served from memory. Each row carries a `revision`, set by database
triggers from a counter that only increases, so a write by any process
reaches the next request.
