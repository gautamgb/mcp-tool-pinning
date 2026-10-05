# mcp-tool-pinning

Prototype for the MCP SEP draft "Client-Held Tool Definition Pinning"
(draft text: https://gist.github.com/gautamgb/1e12c07f466389caf5af6715ee367873).

A host that pins tools computes a digest of each tool definition it receives, stores the
digest when the user approves the tool, and checks it again on every `tools/list`. A tool
whose definition changed stays hidden from the model, and calls to it are refused, until
the new definition is approved.

## Run it

Needs Python 3.12 and [uv](https://docs.astral.sh/uv/).

    uv sync
    uv run python -m mcp_tool_pinning.demo
    uv run pytest -q

The demo server can also run over stdio, for other MCP clients:

    uv run python -m mcp_tool_pinning.demo_server

## What the demo shows

The demo server copies the trigger Pillar Security reported for Deadbugz: after three
`tools/call` requests from the same client, its `tools/list` response changes the
`summarize` description. Here the change is an inert marker line. The server sends no
`list_changed` notification.

1. A scanner connects, lists tools and disconnects. It never calls a tool, so it sees the
   original definitions.
2. An unpinned client makes three calls and lists again. The marker line reaches the model.
3. A pinned client does the same. `summarize` is withheld, the call to it is refused, and
   the diff against the pinned definition is shown.
4. The scanner's Tool Set Digest and the pinned client's disagree: the server served them
   different definitions (SEP section 5).

## Layout

- `digest.py`: Tool Definition Digest and Tool Set Digest (SEP sections 1 and 2). SHA-256
  over the RFC 8785 form of the raw `Tool` object, with the top-level `_meta` removed.
- `session.py`: `PinnedClientSession`, a `ClientSession` subclass implementing section 3.
- `store.py`: JSON pin store. The host chooses one file per server identity.
- `demo_server.py`, `demo.py`, `connect.py`: the demo and an in-process connection helper.
- `vectors/tools.json`: test vectors. `xcheck/` recomputes them with an independent RFC
  8785 implementation (npm `canonicalize`): `cd xcheck && npm install && node xcheck.mjs`.

## Design notes

The digest is computed over the raw JSON of the `tools/list` result. The SDK's pydantic
`Tool` model drops members it does not recognise, so a digest of the parsed model would not
cover what the server actually sent.

`PinnedClientSession.list_tools` makes one request and uses that one response for the
digest, for the SDK's per-tool state and for what the model sees. Fetching twice would let
a server answer the two requests differently.

`approve(name, digest)` takes the digest the user reviewed, so a definition that changes
again between review and approval is not approved by accident. Each pending item carries
its own diff, so the diff shown and the digest approved come from the same listing.

A tool is callable only if it is in the listing the model was given. A name that appears
twice in one listing is withheld, every copy.

The SDK's `call_tool` can itself issue a `tools/list` when it has no output schema for a
tool. That listing goes through the same checks and replaces the current approvals.

The top-level `_meta` is outside the digest and is passed through to the host unpinned. A
host that shows `_meta` content to the model has to pin it separately.

## Findings so far

The first cross-check against npm `canonicalize` disagreed on one vector, an integer above
2^53. The `rfc8785` package rejects it, but JavaScript's `JSON.parse` rounds it before any
digest code runs, so a JavaScript host would compute a digest where a Python host computes
none. The package also rejects every integer at or above 2^53, including exactly
representable ones, while the same magnitude written in exponent form (`1e20` against
`100000000000000000000`) passes. The prototype now applies one rule to the parsed value: a
definition containing any number that is not finite, or whose magnitude is 2^53 or more,
has no digest. Python and JavaScript reach the same answer under that rule, and all 16
vectors agree.

## Limits

This is a proof of concept. Not covered: automatic approval policies, prompts and resource
templates, the HTTP transport, server-published digests, and tamper protection or locking
for the pin store. Pinned to `mcp==2.2.0`; `list_tools` relies on the SDK's
`_absorb_tool_listing`, which the SDK's own `Client` also calls.

## Licence

Apache-2.0.
