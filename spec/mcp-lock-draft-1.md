# MCP tool lock format, draft 1

Draft 1. Not stable. Files written against it carry lockVersion 1-draft and a future version 1
reader rejects them.

- Author: Gautam Bharti
- Date: 2026-10-19
- Builds on: SEP draft "Client-Held Tool Definition Pinning" (Tool Definition Digest)
- Test vectors: `vectors/` in this repository, tag `vectors-draft-1`

## 1. Scope

A lock is a set of files, kept in a repository, that records which tool definitions a person
approved for each MCP server. A host in lock mode checks every `tools/list` result against the
lock, shows the model only approved tools, and refuses calls to anything else. The lock changes
only when someone approves a definition.

This document defines the digests a lock records, how a server is identified, the files and
their contents, the check a host runs, the reason codes it reports, and the event records it
writes. Approval workflows, policy rules, overrides and database storage are outside it.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

"Host" means the component that receives the `tools/list` result from the server and decides
what the model sees: a host application, or a proxy or gateway in front of one. "Lock root" is
the directory that contains `.mcp/`. The host gets the lock root, the posture and any signing
identity from its own configuration.

## 2. Digests

### 2.1 Tool digest

The tool digest is the SEP Tool Definition Digest: take the `Tool` object exactly as received,
remove the top-level `_meta` member, serialize under RFC 8785, hash the UTF-8 bytes with SHA-256,
and write `sha256:` followed by 64 lower-case hex characters. `_meta` members below the top
level are kept. Every other member is covered, including members this draft does not know.

A tool has no digest if any of these hold:

1. It contains a number that is not finite, or whose magnitude is 2^53 or greater. The check
   applies to the parsed value.
2. A member name or string value anywhere outside the removed top-level `_meta` contains an
   unpaired UTF-16 surrogate: a code point in U+D800 to U+DFFF that is not half of a valid
   pair. JSON text can carry one as a `\uD800` escape; UTF-8 cannot encode it, so RFC 8785
   cannot serialize it. A host MUST test for this explicitly before canonicalizing, so the
   result does not depend on how a canonicalization library fails. A valid escaped pair is one
   code point and gets a digest.
3. It cannot otherwise be serialized under RFC 8785.

A host computes the digest over the raw JSON of the result, before any SDK model parses it.
Models that drop unknown members, or JSON parsers that drop or rename keys such as
`__proto__`, produce a different value from the one the server sent. Parsing MUST keep every
member name as given and MUST NOT normalize Unicode: a name in NFC and the same name in NFD are
different names and give different digests.

Text that is not JSON has no digest. Some parsers accept `NaN` and `Infinity` (Python's
`json.loads` does); the number rule above then applies and the result is the same.

When a member name repeats within one object, the digest is computed over what the host's
parser returns. The common parsers keep the last value. See section 11.

### 2.2 Instructions digest

The instructions digest is SHA-256 over the RFC 8785 serialization of the server's
`instructions` value as a JSON string (that is, the quoted, escaped string), in the same
`sha256:` form. Instructions that are not a string, or that contain an unpaired surrogate, have
no digest.

## 3. Server identity

A server's identity is a JSON object of one of three forms. It names the server, not one
running copy of it: version, launch arguments and OAuth audience go in shard attributes
(section 5.2), and the digests decide whether anything that matters changed.

### 3.1 Remote

    {"kind": "remote", "url": "<normalized URL>"}

The URL is normalized as follows:

- The scheme MUST be `http` or `https`, and is written in lower case.
- The URL MUST be ASCII. A writer converts an internationalized host name to its A-label form
  before normalizing.
- The host is written in lower case. An IPv6 literal keeps its brackets.
- A default port (80 for http, 443 for https) is removed. Any other port is kept.
- Userinfo, query and fragment are removed.
- The path is kept exactly as given, including case, percent-encoding and a trailing slash.
  An empty path stays empty. `https://a.example/mcp` and `https://a.example/mcp/` are two
  identities, as are `https://a.example` and `https://a.example/`.

### 3.2 Stdio

    {"kind": "stdio", "package": "<registry>:<name>"}
    {"kind": "stdio", "command": "<basename>"}

`registry` is one of `npm`, `pypi` or `oci`. The name excludes any version, tag or digest:

- `npm`: the package name as published, scope included (`npm:@example/docs-server`).
- `pypi`: the name normalized as in PEP 503: lower case, runs of `-`, `_` and `.` replaced by
  one `-`.
- `oci`: registry host (with port, if any) and repository, lower case, with the `:tag` and
  `@sha256:` parts removed.

Names are printable ASCII without spaces.

The `command` form is used only when the server has no registry coordinate. Its value is the
basename of the command: it MUST NOT contain `/` or `\`, and MUST NOT be `.` or `..`.

An identity object has exactly the members shown for its form. A reader that meets another
`kind`, or other members, reports `lock-unsupported`. A remote URL that is not already in
normalized form, a package with an unknown registry, or a command that is not a basename is
`lock-unreadable`.

### 3.3 Identity key and h16

The identity key is the RFC 8785 serialization of the identity object, as UTF-8 bytes. `h16` is
the first 16 hex characters of SHA-256 over the identity key.

### 3.4 Slug

The slug is a readable prefix for the shard filename. A writer derives it as follows:

1. Source text: for a remote identity, the host followed by the path
   (`mcp.example.com/v1/mcp`); for a package, the name after the registry prefix; for a
   command, the command.
2. Lower-case ASCII letters A-Z.
3. Replace each run of characters outside `a-z` and `0-9` with one `-`.
4. Trim `-` from both ends, cut to 48 characters, trim a trailing `-` again.
5. If nothing is left, use `server`.

Readers check that a filename has slug syntax (section 4.1) but MUST NOT reject a shard because
its slug differs from the one they would derive. The h16 binds the file to its identity.

## 4. Layout

### 4.1 Files

    .mcp/lock/<slug>--<h16>.json         one shard per server (section 5)
    .mcp/lock/aliases.json               optional (section 7)
    .mcp/lock/MANIFEST.json              optional; required when signing (section 8)
    .mcp/lock/MANIFEST.json.sigstore     signature over MANIFEST.json (section 8)
    .mcp/contracts/sha256-<hex>.json     contract files (section 6)

A shard filename matches `^[a-z0-9]+(-[a-z0-9]+)*--[0-9a-f]{16}\.json$` with a slug part of at
most 48 characters. There is no index file: the set of locked servers is the set of shard
filenames. Two shards whose identities have the same identity key are `lock-unreadable`.

`.mcp/lock` contains only the files above. A subdirectory or any other file there is
`lock-unreadable`. `.mcp/contracts` may hold contract files that no shard references; readers
ignore them.

### 4.2 Path rules

A reader or writer touches only `.mcp/lock` and `.mcp/contracts` under the lock root. It
refuses, with `lock-unreadable`:

- a reference that contains `..`, a path separator, or is absolute. The only references in
  draft 1 are contract filenames, which MUST match `^sha256-[0-9a-f]{64}\.json$`, and manifest
  keys, which MUST be filenames in `.mcp/lock`;
- `.mcp`, `.mcp/lock` or `.mcp/contracts` being a symlink or not a directory;
- any file it reads being a symlink or not a regular file;
- any filename in `.mcp/lock` that is not ASCII.

A missing `.mcp/lock` is `lock-unreadable`. An empty `.mcp/lock` is a valid lock with no
servers.

### 4.3 Reading lock files

Every file in `.mcp/lock` is UTF-8 JSON. A reader MUST reject, as `lock-unreadable`, a lock file
that is not valid JSON, that repeats a member name within one object, or that uses `NaN` or
`Infinity`. Lock files are written by tools, so a strict parser costs nothing; listings from
servers cannot be held to the same rule (section 11).

A reader reads each file's bytes once and verifies and parses those same bytes. It loads the
lock as a unit: a failure in any file under `.mcp/lock`, or in any contract a shard references,
fails the whole load, and section 9.4 applies to every server.

Type errors and missing required members are `lock-unreadable`. A member, `lockVersion`,
identity `kind` or `via` value that draft 1 does not define is `lock-unsupported`, so that a
reader can tell an old reader from a damaged file.

## 5. Shard

### 5.1 Members

    {
      "lockVersion": "1-draft",
      "identity": {"kind": "remote", "url": "https://mcp.example.com/v1/mcp"},
      "attributes": {"version": "1.4.0", "env": ["DOCS_TOKEN"]},
      "instructions": {"digest": "sha256:..."},
      "tools": {
        "search": {
          "digest": "sha256:<64 hex>",
          "contract": "sha256-<64 hex>.json",
          "approval": {"subject": "github:docs-owner", "at": "2026-10-19T17:00:00Z",
                       "via": "pr", "ref": "pr-42"}
        }
      }
    }

- `lockVersion` (required): `"1-draft"`. Any other value is `lock-unsupported`. A reader checks
  it before any other member.
- `identity` (required): section 3. Its h16 MUST equal the h16 in the filename, else
  `lock-unreadable`.
- `attributes` (optional): informational only and never an input to the check. Members:
  `version`, `audience`, `command` (strings), `args` (array of strings), `env` (array of
  environment variable names matching `^[A-Za-z_][A-Za-z0-9_]*$`; never values). A writer MUST
  NOT write secrets into `args`.
- `instructions` (optional): `{"digest": "<instructions digest>"}`.
- `tools` (required): an object keyed by tool name. Each entry has exactly:
  - `digest`: the approved tool digest.
  - `contract`: the contract filename for that digest (section 6).
  - `approval`: `subject` (string), `at` (RFC 3339 time), `via` (one of `pr`, `runtime`, `api`,
    `migrated`) and optionally `ref` (string: a commit, ticket or event id).

Any other top-level member, any other member in a tool entry or approval, or another `via`
value is `lock-unsupported`.

### 5.2 Approval records (informative)

`subject` records who approved, but a value typed by a pull request author is that author's
claim. A CI path that writes approvals records the merge commit in `ref`, and the signature
(section 8) records who signed. `via: migrated` marks an entry created by a one-time operator
command from a pin taken under an earlier scheme, after confirming the served tool still
matched it. A host in lock mode never migrates or approves on its own.

## 6. Contract files

`.mcp/contracts/sha256-<hex>.json` holds the approved definition. Its bytes are exactly the
RFC 8785 serialization of the tool with the top-level `_meta` removed, so SHA-256 of the file
bytes is the tool digest. There is no trailing newline.

For every tool entry a reader checks that the `contract` value is `sha256-<hex>.json` where
`<hex>` is the hex part of the entry's `digest`, that the file exists, and that SHA-256 of its
bytes equals `<hex>`. Any failure is `contract-mismatch`. A contract value that is not a
contract filename is a path error, `lock-unreadable` (section 4.2).

Reviewers SHOULD see diffs rendered from contract files, never from text a server supplied at
review time.

## 7. Aliases

Hosts keep their own names for servers. `aliases.json` maps those names to identities, so
renaming a host entry does not change which shard applies and machines can share one lock:

    {"lockVersion": "1-draft",
     "aliases": {"docs": {"kind": "remote", "url": "https://mcp.example.com/v1/mcp"}}}

Each value is an identity object and is validated as in section 3. An alias resolves to an
identity; the check then uses that identity's shard. When the lock is signed, the alias map is
covered by the manifest like any other file.

## 8. Manifest and signing

### 8.1 Manifest

    {"lockVersion": "1-draft", "sequence": 7,
     "files": {"<filename in .mcp/lock>": "sha256:<hex of file bytes>"}}

`files` covers every file in `.mcp/lock` except `MANIFEST.json` and `MANIFEST.json.sigstore`.
When a manifest is present, the set of those files on disk MUST equal the set of `files` keys
exactly, and each file's SHA-256 MUST equal its entry. An extra file, a missing file or a
different hash is `lock-unreadable`. `sequence` is a non-negative integer that a writer
increases on every change.

Contract files are not listed. Each is bound by the digest in a shard, and the shard is bound
by the manifest.

A host MAY require a manifest by configuration; a missing one is then `lock-unreadable`.

### 8.2 Signing

`MANIFEST.json.sigstore` is a Sigstore bundle over the exact bytes of `MANIFEST.json`.

Whether a host requires a signature, and which signer identity it accepts (certificate issuer
and subject), are host configuration held outside the lock repository. Neither is ever read
from the lock or from an environment variable that the lock repository can set.

With a signer identity configured, a host MUST, in this order:

1. require `MANIFEST.json` and `MANIFEST.json.sigstore`;
2. verify the bundle over the manifest bytes against the configured identity, with the trust
   root the host is configured with;
3. parse the manifest and refuse a `sequence` lower than the last value it accepted for this
   lock;
4. check the file set and hashes (section 8.1) and continue reading.

A failure in steps 1 to 3 is `lock-signature-invalid`, in every posture. A host that supports
signing as an optional component and finds it absent while an identity is configured fails the
same way. A host without a configured identity does not verify and MUST NOT describe the lock
as signed.

## 9. Check

### 9.1 Postures

The posture comes from host configuration: `monitor` or `guard`. `strict` is accepted and
behaves as `guard` in draft 1. Under `guard` the host enforces; under `monitor` it reports
and changes nothing the model sees, except under section 9.4.

### 9.2 Listing

A listing is one complete `tools/list` result, all pages collected, received on the connection
the model uses. The host checks each listing it receives, including the first on every
connection, and uses the same result for the check and for what the model sees. It never
fetches a second time to compute digests.

The host finds the shard whose identity key equals the server's identity key, then gives each
tool in the listing the first reason that applies:

| Reason | Applies when |
|---|---|
| `unlocked-server` | no shard for this identity (applies to every tool) |
| `duplicate-name` | another tool in the same listing has the same name (every copy) |
| `no-digest` | the tool has no digest (section 2.1) |
| `new-tool` | the name is not in the shard's `tools` |
| `upstream-changed` | the digest differs from the approved digest |

A tool with none of these is approved: shown and callable. Under `guard` a tool with a reason is
withheld: the model does not see it. Under `monitor` it is shown and reported with its reason.

A listing entry that is not an object with a string `name` is never shown and cannot be called.

Names in the shard that are absent from the listing are reported as removed. Removal is not a
failure.

### 9.3 Instructions

If the server sent instructions and the shard has no instructions digest, or the served
instructions' digest differs from it or does not exist, the reason is `instructions-changed`.
Under `guard` the host withholds the instructions from the model; a host that cannot strip them
withholds every tool of that server instead. Under `monitor` it reports. A shard with an
instructions digest and a server that sends none is not a failure.

### 9.4 Whole-lock failures

`lock-unreadable`, `lock-unsupported`, `lock-signature-invalid` and `contract-mismatch` mean the
host has no lock it can trust. In every posture, monitor included, it withholds every tool of
every server and the instructions, and refuses every call with that reason, until a load
succeeds.

### 9.5 Calls

A host allows `tools/call` only for a name shown on this connection's latest listing. The check
is an allow-list built from that listing, never a deny-list of withheld names. A refused call
gets a JSON-RPC error and is not sent to the server:

    {"code": -32011, "message": "Tool withheld by lock",
     "data": {"reason": "upstream-changed", "tool": "fetch"}}

`data.reason` is the tool's reason from section 9.2 when the name was withheld, the lock
failure under section 9.4, `no-listing` when no listing has been checked on this connection,
and `not-listed` when the name was not in the latest listing.

Code -32011 is distinct from -32010, which the same hosts use for drift holds outside lock mode.

### 9.6 No first use, no re-pin

A host in lock mode does not approve a tool because it is seen for the first time, does not
replace an approved digest with a served one, and does not migrate pins at runtime. The lock
changes only by approval, written to the lock files by a person's action or by a process that
person authorized.

### 9.7 Reason codes

| Code | Scope |
|---|---|
| `new-tool`, `upstream-changed`, `no-digest`, `duplicate-name` | one tool |
| `unlocked-server` | every tool of one server |
| `instructions-changed` | the server's instructions |
| `lock-unreadable`, `lock-unsupported`, `lock-signature-invalid`, `contract-mismatch` | the whole lock |
| `no-listing`, `not-listed` | one call |
| `classifier-error` | a host's change classifier failed; the decision does not proceed |
| `unreachable` | the host could not get a listing from the server |

`classifier-error` and `unreachable` are defined for hosts and have no vectors. A host that
labels changes for reviewers MUST NOT let a classifier error lead to a tool being shown.

## 10. Events

A host records decisions as JSON objects, one per line. Every event has:

- `schema`: `"mcpindex.lock.event/1"`
- `type`: `listing`, `refusal`, `approval` or `override`
- `id`: unique string
- `time`: RFC 3339
- `host`: the host's configured name
- `server`: `{"h16": "<h16>", "slug": "<slug>"}`

By type:

- `listing`, one per checked listing: `posture`, `lockError` (code or null), `counts`
  (`served`, `shown`, `withheld`, `removed`), `tools` (array of `{"name", "served", "approved",
  "decision", "reason"}`, where `served` and `approved` are digests or null, `decision` is
  `shown` or `withheld`, and `reason` is a code or null), `removed` (names) and `instructions`
  (code or null).
- `refusal`: `tool`, `reason`.
- `approval`: `tool`, `digest`, `via`, `subject`, `ref`.
- `override`: `posture`, `until`, `subject`, `ref`. The override record itself is not part of
  draft 1.

Events never contain call arguments, call results, descriptions, instructions text or
credentials. Tool names come from the server and are untrusted text; consumers escape them.

    {"schema": "mcpindex.lock.event/1", "type": "listing", "id": "01JAX3...",
     "time": "2026-10-19T17:05:00Z", "host": "ci-runner-3",
     "server": {"h16": "022711de5f88d01f", "slug": "mcp-example-com-v1-mcp"},
     "posture": "guard", "lockError": null,
     "counts": {"served": 2, "shown": 1, "withheld": 1, "removed": 0},
     "tools": [
       {"name": "search", "served": "sha256:...", "approved": "sha256:...",
        "decision": "shown", "reason": null},
       {"name": "fetch", "served": "sha256:...", "approved": "sha256:...",
        "decision": "withheld", "reason": "upstream-changed"}],
     "removed": [], "instructions": null}

## 11. Known limits

- A matching digest says the definition is the one approved. It says nothing about what the
  server does when the tool is called.
- Duplicate member names in a served tool are digested as the host's parser returns them, which
  for the common parsers is the last value. Two parsers that resolve duplicates differently
  compute different digests for the same bytes. Detecting duplicates needs the raw message
  text, which most SDKs do not expose; draft 1 does not require it.
- A CI check that lists a server to compare against the lock uses its own connection, and a
  server can answer it differently from the host's connection. Its result is advisory. Only the
  host's check on the connection the model uses enforces anything.
- `_meta` is outside the tool digest. A host that shows `_meta` content to the model has to pin
  it by other means.
- Without a configured signer, anyone who can write to the repository can change the lock.
  Repository review is then the only control.
- The `sequence` rule protects only against rollback to a manifest older than one the host has
  already accepted.

## 12. Test vectors

`vectors/` holds:

- `tools.json`: parsed tool digest cases.
- `digest/<case>.json` and `digest/index.json`: raw-text cases. The file bytes are the input;
  `index.json` maps each case to the expected digest or null and a note. Implementations parse
  the text with their own JSON parser.
- `identity.json`: identity normalization, identity keys, h16, slugs and filenames.
- `lock/<case>/`: a lock root (`.mcp/`), `listing.json` (absent when the case has no listing),
  `server.json` (the identity), `config.json` (`posture`, and optionally `requireManifest`,
  `signer`, `lastSequence`), `expected.json` and, where needed, `setup.json`, which lists
  symlinks and files the test runner creates before running the case. `expected.json` has
  `lockError`, `shown` (names in listing order), `withheld` and `flagged` (name to reason,
  for guard and monitor respectively), `removed`, `instructions`, `stripInstructions` and
  `calls` (name to `allow` or a reason).
- `SHA256SUMS`: SHA-256 of every file above, for vendoring.

The vectors include no valid Sigstore bundle. The two signing cases expect
`lock-signature-invalid` from a missing bundle and from a placeholder bundle.
