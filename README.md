# mcp-tool-pinning

Prototype for the MCP SEP draft "Client-Held Tool Definition Pinning"
(draft text: https://gist.github.com/gautamgb/1e12c07f466389caf5af6715ee367873).

A host that pins tools computes a digest of each tool definition it receives, stores the
digest when the user approves the tool, and checks it again on every `tools/list`. A tool
whose definition changed stays hidden from the model, and calls to it are refused, until
the new definition is approved. Prompts and resource templates are pinned the same way
(SEP section 4).

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
   the diff against the pinned definition is shown. The server also switches the `review`
   prompt's description, so that prompt is withheld and `prompts/get` is refused.
4. The scanner's Tool Set Digest and the pinned client's disagree: the server served them
   different definitions (SEP section 5).

## Conformance scenario

    uv run python -m mcp_tool_pinning.scenario

A draft of the client conformance scenario for rule 3.4, with the test design from
Paolo Costanzo's tool-change lab: serve definition A and call it, serve A again (the call
must reach the server), serve B (it must not), then reconnect while B is served (still no
call). It runs two hosts. The pinned client passes. A plain client with an "always allow"
list of tool names, the approval model Paolo found in the clients he tested, fails at the
switch. Sending `list_changed` with the switch is not covered here; Paolo's lab runs that
against real clients.

## Layout

- `digest.py`: Definition Digest and Set Digest (SEP sections 1, 2 and 4). SHA-256 over the
  RFC 8785 form of the raw `Tool`, `Prompt` or `ResourceTemplate` object, with the top-level
  `_meta` removed.
- `session.py`: `PinnedClientSession`, a `ClientSession` subclass implementing sections 3
  and 4.
- `store.py`: JSON pin store, pins kept per kind and name. The host chooses one file per
  server identity.
- `uritemplate.py`: RFC 6570 level 1 expansion for reading through an approved template.
- `scenario.py`: the draft conformance scenario above.
- `demo_server.py`, `demo.py`, `connect.py`: the demo and an in-process connection helper.
- `vectors/tools.json` and `vectors/definitions.json` (prompts and templates): test vectors.
  `xcheck/` recomputes them with an independent RFC
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
twice on one page is withheld, every copy. If the second copy arrives on a later page, the
earlier page has already been returned with the first copy in it; from then on the call is
refused, and a host should drop that entry from what it took from earlier pages. The same
holds for prompts (`get_prompt` is refused) and templates. `complete` is refused for a
prompt or template that is not approved, since it sends the user's partial input to the
server for that prompt or template.

Templates are read through `read_template(name, variables)`, which expands only an approved
template. `read_resource` is not gated: a concrete resource from `resources/list` is not a
pinned definition, and a URI the host builds some other way never passed through a template
the session can check. Expansion supports simple `{var}` expressions only and refuses
anything else. It is stricter than RFC 6570 in a few places: a missing variable, a value of
`.` or `..`, and literal characters outside the RFC's set are all refused.

`pending()` and `approve()` take a kind (`"tools"`, `"prompts"` or `"resourceTemplates"`,
default `"tools"`). A tool and a prompt with the same name have separate pins. Pin files
written before prompts and templates were pinned load unchanged.

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
has no digest. Python and JavaScript reach the same answer under that rule. All 22 vectors
(16 tools, 6 prompts and templates) agree.

## Limits

This is a proof of concept. Not covered: automatic approval policies, RFC 6570 expressions
beyond level 1, `list_changed` in the conformance scenario, the HTTP transport, server-published digests, and tamper protection or locking
for the pin store. Pinned to `mcp==2.2.0`; `list_tools` relies on the SDK's
`_absorb_tool_listing`, which the SDK's own `Client` also calls.

## Licence

Apache-2.0.
