# MCP tool lock format, draft 1c

Draft 1c. Not stable. Files written against it carry lockVersion 1-draft and a future version 1
reader rejects them. Section 13 lists what changed from draft 1b.

- Author: Gautam Bharti
- Date: 2026-10-19
- Builds on: SEP draft "Client-Held Tool Definition Pinning" (Tool Definition Digest)
- Test vectors: `vectors/` in this repository, tag `vectors-draft-1c`

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

The top-level `_meta` is outside the digest, so the digest says nothing about it. A lock
approves it separately through the meta digest (section 2.3), and section 9.2.3 says what a
host relays. A host MUST NOT place `_meta` in model context.

A tool has no digest if any of these hold:

1. It contains a number that is not finite, or whose magnitude is 2^53 or greater. The check
   applies to the parsed value.
2. A member name or string value anywhere outside the removed top-level `_meta` contains an
   unpaired UTF-16 surrogate: a code point in U+D800 to U+DFFF that is not half of a valid
   pair. JSON text can carry one as a `\uD800` escape; UTF-8 cannot encode it, so RFC 8785
   cannot serialize it. A host MUST test for this explicitly before canonicalizing, so the
   result does not depend on how a canonicalization library fails. A valid escaped pair is one
   code point and gets a digest.
3. It has a value nested more than 512 levels deep. The tool object is at depth 0, and a
   member value or array element is one level deeper than the object or array that holds it.
   A host tests this before canonicalizing, for the same reason as rule 2, and so that a
   deeply nested listing cannot exhaust its stack.
4. It cannot otherwise be serialized under RFC 8785.

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

### 2.3 Meta digest

The meta digest is SHA-256 over the RFC 8785 serialization of a tool's top-level `_meta`
value, in the same `sha256:` form. A `_meta` that is not an object has no meta digest, and
neither does one that the rules of section 2.1 exclude, counting `_meta` at depth 1 as it sits
in the tool.

## 3. Server identity

A server's identity is a JSON object of one of three forms. It names the server, not one
running copy of it: version and OAuth audience go in shard attributes (section 5.1), and the
digests decide whether anything that matters changed. Launch arguments are attributes too,
except in the command form (section 3.2), where they are part of the identity.

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
    {"kind": "stdio", "command": "<basename>", "args": ["<arg>", ...]}

`registry` is one of `npm`, `pypi` or `oci`. The name excludes any version, tag or digest:

- `npm`: the package name as published, scope included (`npm:@example/docs-server`).
- `pypi`: the name normalized as in PEP 503: lower case, runs of `-`, `_` and `.` replaced by
  one `-`.
- `oci`: registry host (with port, if any) and repository, lower case, with the `:tag` and
  `@sha256:` parts removed.

Names are printable ASCII without spaces.

The `command` form is used only when the launch line gives no registry coordinate. `command` is
the basename of the command as launched: everything up to the last `/` or `\` is removed, and
the result MUST NOT be `.` or `..`. `args` is every argument after the command, in order and
verbatim; a path among them is kept as given, and no arguments is `[]`. Without `args`, every
launch of one tool that a host cannot parse (`uvx git+https://...` naming two different
repositories, say) would share one identity and one shard.

Identity derivation fails, with an error that names the rule, if any argument is
secret-looking (section 3.2.1) or contains an unpaired surrogate. A writer does not strip the
argument and carry on, since the result would no longer describe the launch.

Because the arguments are verbatim, a path that differs between machines gives each machine its
own identity. Hosts SHOULD name such servers by an alias (section 7), so the identity is written
once in the lock instead of being derived from each machine's launch line.

### 3.2.1 Secret-looking arguments

The rules below are ASCII-only. Letters match without regard to case, `[...]` classes contain
only the ASCII characters listed, and `\b` is a boundary between `[A-Za-z0-9_]` and any other
character or either end of the text. An argument is secret-looking if any of these holds:

1. It contains a match for one of these patterns:

        ^(bearer|basic|token)[ \t]+[^ \t]
        \bsk-[A-Za-z0-9_-]{16,}
        \bsk_(live|test)_[A-Za-z0-9]{10,}
        \bgh[pousr]_[A-Za-z0-9]{20,}
        \bgithub_pat_[A-Za-z0-9_]{20,}
        \bglpat-[A-Za-z0-9_-]{16,}
        \bxox[abprs]-[A-Za-z0-9-]{10,}
        \bAKIA[0-9A-Z]{16}\b
        \bAIza[0-9A-Za-z_-]{30,}
        \bnpm_[A-Za-z0-9]{30,}
        -----BEGIN [A-Z ]*PRIVATE KEY
        \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.

2. It starts with `-`, its name (the text before the first `=`) is a secret name, and it
   either has a non-empty value after `=` or is followed by an argument that does not start
   with `-` (that argument is its value).
3. It has the form `NAME=value`, where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*` and is a secret
   name.
4. It contains `://`, and either the authority (the text after the first `://` up to the first
   `/`, `?` or `#`) has a `:` before its last `@`, which is a password, or the query (the text
   after the first `?` up to the first `#`) has a parameter, split on `&`, whose name before
   `=` is a secret name.

A name is a secret name if, after removing leading `-`, lower-casing and splitting on runs of
`-`, `_` and `.`, one of its segments, or all segments joined, is one of: `token`, `secret`,
`password`, `passwd`, `pwd`, `apikey`, `auth`, `authorization`, `credential`, `credentials`,
`bearer`, `cookie`, `key`, `pat`, `privatekey`, `session`. Segments are matched whole, so
`--author` and `--keyword` are not secret names. A user name without a password, as in
`git+ssh://git@github.com/...`, is not secret-looking. Rules 1 to 3 are the ones a writer
already applies to `attributes.args` (section 5.1). A writer may strip userinfo and queries from
URLs in attributes, but an identity keeps its arguments verbatim, so rule 4 refuses them
instead.

An identity object has exactly the members shown for its form. A reader that meets another
`kind`, or other members, reports `lock-unsupported`; that includes a command identity without
`args`. A remote URL that is not already in normalized form, a package with an unknown
registry, a command that is not a basename, or `args` that is not an array of strings or that
identity derivation would refuse is `lock-unreadable`.

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

Every number in a lock file MUST be an integer token: an optional `-` followed by digits, with
no fraction and no exponent. `1.0` and `1e0` are `lock-unreadable` even where a parser returns
the integer 1; a reader whose parser does not keep that distinction checks the raw text.

Type errors and missing required members are `lock-unreadable`. A member, `lockVersion`,
identity `kind` or `via` value that draft 1 does not define is `lock-unsupported`, so that a
reader can tell an old reader from a damaged file.

### 4.4 Syntax

Every pattern in this document matches the whole value and only ASCII. `[0-9]` is the ten ASCII
digits, so a digit from another script does not match, and no pattern accepts a trailing line
break. This covers digests (`sha256:[0-9a-f]{64}`), approval times, shard and contract
filenames, slugs, h16 and environment variable names. An approval time matches

    [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})

A value that would match only under a Unicode digit class, or only with a trailing newline, is
`lock-unreadable`.

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
- `tools` (required): an object keyed by tool name. Each entry has:
  - `digest` (required): the approved tool digest.
  - `contract` (required): the contract filename for that digest (section 6).
  - `approval` (required): `subject` (string), `at` (RFC 3339 time, section 4.4), `via` (one
    of `pr`, `runtime`, `api`, `migrated`) and optionally `ref` (string: a commit, ticket or
    event id).
  - `metaDigest` (optional): the meta digest (section 2.3) of the tool's top-level `_meta` as
    approved. A writer records it whenever the tool it approves has a top-level `_meta` with a
    meta digest, and omits it otherwise. A value that is not a digest is `lock-unreadable`.

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
different hash is `lock-unreadable`. `sequence` is an integer from 0 to 2^53 - 1 that a writer
increases on every change.

Contract files are not listed. Each is bound by the digest in a shard, and the shard is bound
by the manifest.

A host MAY require a manifest by configuration; a missing one is then `lock-unreadable`.

### 8.2 Signing

`MANIFEST.json.sigstore` is a Sigstore bundle over the exact bytes of `MANIFEST.json`.

Whether a host requires a signature, and which signer identity it accepts (certificate issuer
and subject), are host configuration held outside the lock repository. Neither is ever read
from the lock or from an environment variable that the lock repository can set.

A host with a signer identity configured MUST also be configured with a sequence store: a
place outside the lock repository where it keeps the highest `sequence` it has accepted for
this lock. Without one, step 3 below has nothing to compare against, and a validly signed older
manifest would be accepted after a newer one. A host configuration that names a signer and no
sequence store is refused when the host loads it, with `lock-signature-invalid` and a detail
that names the missing sequence store.

With a signer identity configured, a host MUST, in this order:

1. require `MANIFEST.json` and `MANIFEST.json.sigstore`;
2. verify the bundle over the manifest bytes against the configured identity, with the trust
   root the host is configured with;
3. parse the manifest and refuse a `sequence` lower than its floor: the larger of the value in
   the sequence store and the highest value this reader has accepted since it was created;
4. check the file set and hashes (section 8.1) and continue reading.

A reader keeps the floor in memory for each store it reads, so a sequence store that is
deleted or rewritten while the host runs does not lower it. After accepting a manifest, the
host writes its `sequence` to the store when it is higher than the stored value.

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

### 9.2.1 Listing in progress

A listing starts when the host sends `tools/list` without a cursor: for a proxy, when it relays
one from its client; for a host that collects the pages itself, when it asks for the first
page. It ends when the page without `nextCursor` has been checked, or when it fails (section
9.5). While a listing is in progress, every `tools/call` is refused with `no-listing`,
including calls to names that the previous listing allowed. A cursorless `tools/list` sent
while a listing is in progress starts a new listing, and the earlier one is abandoned.

A `notifications/tools/list_changed` from the server does not change the allow-list. It marks a
listing as due. The allow-list changes when the next listing completes, and that listing
replaces it. A host that collects the pages itself SHOULD start a listing when one is due. A
notification that arrives during a listing does not end that listing.

### 9.2.2 Frames that carry tools

Only the response to a `tools/list` request the host sent, and that is still unanswered, can
carry tools to the model. The host matches a response to a request by `id`, comparing JSON
type and value exactly: a string matches only an equal string, and a number only an equal
number. `"1"` does not match `1`, `true` does not match `1`, and `null` matches nothing, so a
`tools/list` sent with a null id never receives a listing. Unanswered `tools/list` requests
are matched first, and the host's unanswered `initialize` request second.

The host drops a frame from the server, and reports it, when the frame:

- is not a JSON object (a batch, for example);
- has a `method` member and also a `result` or `error` member;
- has a `result` object with a `tools` member and does not match an unanswered `tools/list`
  request. This includes a frame with no `id` or a null `id`, an `id` that matches nothing,
  and a match to `initialize`;
- has a `result` object with an `instructions` member and matches neither an unanswered
  `tools/list` request nor the unanswered `initialize` request.

When a dropped frame matches a request the client is waiting on, the host answers that request
with a JSON-RPC error so the client is not left waiting.

### 9.2.3 Top-level `_meta`

For each tool it shows, under `guard`, the host decides the tool's top-level `_meta`:

- a served tool without a top-level `_meta` needs no decision;
- when the entry has a `metaDigest` and the served `_meta` has the same meta digest, the host
  relays `_meta` unchanged;
- when the entry has a `metaDigest` and the served `_meta` has a different meta digest or
  none, the host removes the top-level `_meta` from the tool it relays and flags the tool
  `meta-changed`;
- when the entry has no `metaDigest`, or there is no entry, the host removes the top-level
  `_meta` and flags the tool `meta-unapproved`.

The tool stays shown and callable, since its definition matched; only its metadata is not
relayed. Nothing else in the tool is changed. Under `monitor` the host relays `_meta`
unchanged and reports the same flags.

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

`data.reason` is the first of these that applies:

1. `no-listing`, when a listing is in progress (section 9.2.1) or none has completed on this
   connection;
2. the lock failure, when the latest listing was decided under section 9.4;
3. `unreachable`, when the latest listing on this connection failed;
4. `lock-stale`, under section 9.8;
5. the tool's reason from section 9.2, when the name was withheld;
6. `not-listed`, when the name was not in the latest listing.

A listing fails when the server answers `tools/list` with an error, sends a result without a
`tools` array, cannot be asked for a further page, or exceeds a limit the host sets on pages or
tools. After a failed listing the host refuses every call on that connection with
`unreachable` until a listing completes. It does not fall back to the allow-list of an earlier
listing.

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
| `meta-changed`, `meta-unapproved` | one shown tool's top-level `_meta` (section 9.2.3) |
| `lock-unreadable`, `lock-unsupported`, `lock-signature-invalid`, `contract-mismatch` | the whole lock |
| `no-listing`, `not-listed` | one call |
| `unreachable` | every call on one connection after its latest listing failed (section 9.5) |
| `lock-stale` | every decision made from a snapshot past the host's maximum staleness (section 9.8) |
| `classifier-error` | a host's change classifier failed; the decision does not proceed |

`classifier-error` is defined for hosts and has no vectors. `unreachable`, `lock-stale` and
`no-listing` during a listing are covered by the session vectors (section 12). A host that
labels changes for reviewers MUST NOT let a classifier error lead to a tool being shown.

### 9.8 Snapshots and staleness

A host may load the lock into a snapshot, from files or from another store, and decide several
listings and calls from it. Such a host has a maximum staleness, set by its configuration; the
default is 60 seconds. Before it decides a listing or a call from a snapshot older than that,
it reloads the snapshot. If the reload fails, the decision is refused with `lock-stale`: a
listing is handled as in section 9.4 with that reason, and a call gets `data.reason`
`lock-stale`. The next call tries the reload again.

A call decided from a listing that failed under section 9.4 gets that failure's reason, never
`lock-stale`, and does not trigger a reload: its allow-list is already empty, and only a new
listing can change it.

A reload between listings re-checks the connection's latest listing against the new snapshot.
The new allow-list is the names allowed both before and after the reload, so a reload can
withhold a name, for example after a revocation, but never makes one callable. A name becomes
callable again only through a listing checked under section 9.2.

A host that loads the lock for every listing still holds a snapshot between listings, and the
rules above apply to calls made in that interval.

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
  "decision", "reason", "meta"}`, where `served` and `approved` are digests or null,
  `decision` is `shown` or `withheld`, `reason` is a code or null, and `meta` is
  `meta-changed`, `meta-unapproved` or null), `removed` (names) and `instructions` (code or
  null). It MAY carry `snapshotId`, a string naming the store snapshot the decision
  used; its form is up to the store.
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
        "decision": "shown", "reason": null, "meta": null},
       {"name": "fetch", "served": "sha256:...", "approved": "sha256:...",
        "decision": "withheld", "reason": "upstream-changed", "meta": null}],
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
- The meta digest approves the top-level `_meta` as a whole. When a server changes any part of
  it, a host under `guard` removes all of it, including parts the client relies on, such as a
  UI resource. The tool still works without them.
- Only the frame shapes in section 9.2.2 are dropped. A server can still answer a request the
  host relays with content of its choosing; the lock covers tool definitions and instructions,
  not results.
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
- `identity.json`: identity normalization, identity keys, h16, slugs and filenames. A command
  case gives `command` and `args` as the launch line has them; an `error` case is one where
  derivation fails.
- `lock/<case>/`: a lock root (`.mcp/`), `listing.json` (absent when the case has no listing),
  `server.json` (the identity), `config.json`, `expected.json` and, where needed,
  `setup.json`, which lists symlinks and files the test runner creates before running the
  case, and `session.json`.
- `config.json` has `posture`, and optionally `requireManifest`, `signer`, `sequenceStore`
  (true when the host has a sequence store), `lastSequence` (the value in it), `maxStaleness`
  (seconds, default 60) and `testVerifier`.
- `expected.json` has `lockError`, `shown` (names in listing order), `withheld` and `flagged`
  (name to reason, for guard and monitor respectively), `removed`, `instructions`,
  `stripInstructions`, `calls` (name to `allow` or a reason) and `meta` (for each shown tool
  with a top-level `_meta`, `{"relay": true or false, "flag": "meta-changed",
  "meta-unapproved" or null}`).
- `session.json`, when present, has `steps`: an array run in order against one connection
  whose clock starts at 0. `{"op": "list-start"}` starts a listing; `{"op": "list-complete",
  "listing": "<file>"}` completes it with that file's result, loading the lock for it;
  `{"op": "list-fail"}` fails it; `{"op": "list-changed"}` is a
  `notifications/tools/list_changed`; `{"op": "clock", "advance": <seconds>}` moves the clock;
  `{"op": "write", "path": "<path>", "text": "<text>"}` replaces a file under the case
  directory; and `{"op": "call", "tool": "<name>", "expect": "<allow or reason>"}` is a call
  whose verdict must equal `expect`. The cases assume a host that reloads exactly when the
  snapshot is older than the maximum staleness, no sooner.
- `frames.json`: section 9.2.2. Each case gives `inflight` (ids of unanswered `tools/list`
  requests), optionally `handshake` (the id of the unanswered `initialize`), a `frame` from
  the server and `expect`: `listing` (checked as a page), `handshake` (its instructions are
  checked), `drop` or `relay`.
- `SHA256SUMS`: SHA-256 of every file above, for vendoring.

The vectors include no valid Sigstore bundle. `testVerifier: "accept-any"` tells the test
runner to verify bundles with a stub that accepts any bytes, so that a case can reach the
checks after verification (the sequence floor, for one). It exists only in test runners and is
never a host setting. Without it, a signing case expects `lock-signature-invalid` from a
missing or placeholder bundle.

## 13. Changes from draft 1b

- Section 2.1: a value nested more than 512 levels deep has no digest.
- Sections 2.3, 5.1 and 9.2.3: an optional `metaDigest` per tool entry approves the top-level
  `_meta`; under `guard` an unapproved or changed `_meta` is removed and flagged. A draft 1b
  reader reports a shard that uses it as `lock-unsupported`.
- Section 8.2: a signer requires a sequence store, and readers keep an in-memory floor.
- Section 9.2.1: calls during a listing get `no-listing`, and `list_changed` alone no longer
  changes the allow-list.
- Section 9.2.2: frames that can carry tools or instructions are matched exactly and dropped
  otherwise.
- Section 9.5: the order of call reasons is fixed.
- Section 9.8: the maximum staleness defaults to 60 seconds, a host always tries the reload,
  and a whole-lock failure is reported before `lock-stale`.
- Section 10: listing event tool entries carry `meta`.
