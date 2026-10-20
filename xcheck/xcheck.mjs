// Recompute the vectors with an independent RFC 8785 implementation (npm canonicalize).
//   vectors/tools.json      parsed form
//   vectors/digest/*.json   raw text, through JSON.parse
//   vectors/identity.json   identity key and h16
//   vectors/lock/*/.mcp/contracts/*.json  contract bytes are already in RFC 8785 form
//   vectors/lock/*/                       metaDigest of each _meta the case expects relayed as approved
//   vectors/lock/*/expected.json          the served digest of each tool row in the listing event
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

const vectors = new URL("../vectors/", import.meta.url);
const read = (path) => readFileSync(new URL(path, vectors));
const sha256 = (text) => createHash("sha256").update(text, "utf8").digest("hex");

// SEP section 1: no digest if any number is non-finite or has magnitude >= 2^53.
const inRange = (v) =>
  typeof v === "number" ? Number.isFinite(v) && Math.abs(v) < 2 ** 53
  : Array.isArray(v) ? v.every(inRange)
  : v !== null && typeof v === "object" ? Object.values(v).every(inRange)
  : true;

// No digest if any key or string holds an unpaired UTF-16 surrogate. Checked here rather
// than left to canonicalize, which also rejects them, so the rule does not rest on it.
const LONE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const wellFormed = (v) =>
  typeof v === "string" ? !LONE.test(v)
  : Array.isArray(v) ? v.every(wellFormed)
  : v !== null && typeof v === "object"
    ? Object.keys(v).every((k) => !LONE.test(k)) && Object.values(v).every(wellFormed)
  : true;

// No digest if any value sits deeper than 512, the tool object being depth 0.
const MAX_DEPTH = 512;
const shallow = (v, depth) =>
  depth > MAX_DEPTH ? false
  : Array.isArray(v) ? v.every((x) => shallow(x, depth + 1))
  : v !== null && typeof v === "object" ? Object.values(v).every((x) => shallow(x, depth + 1))
  : true;

const digest = (tool) => {
  const { _meta, ...body } = tool;
  if (!shallow(body, 0) || !wellFormed(body) || !inRange(body)) return null;
  return "sha256:" + sha256(canonicalize(body));
};

const metaDigest = (meta) =>
  meta === null || typeof meta !== "object" || Array.isArray(meta) || !shallow(meta, 1)
    || !wellFormed(meta) || !inRange(meta)
    ? null
    : "sha256:" + sha256(canonicalize(meta));

let total = 0;
let failed = 0;
const report = (ok, label, detail) => {
  total++;
  if (!ok) failed++;
  console.log(`${ok ? "match   " : "MISMATCH"} ${label}  ${detail}`);
};

for (const v of JSON.parse(read("tools.json"))) {
  const js = digest(v.tool);
  report(js === v.expected, `tools.json ${v.name}`, js ?? "no digest");
}

const index = JSON.parse(read("digest/index.json"));
for (const [name, { expected }] of Object.entries(index)) {
  let js;
  try {
    js = digest(JSON.parse(read(`digest/${name}.json`).toString("utf8")));
  } catch {
    js = null; // not JSON (NaN, Infinity): no digest
  }
  report(js === expected, `raw ${name}`, js ?? "no digest");
}

for (const c of JSON.parse(read("identity.json"))) {
  if (c.error) continue;
  const key = canonicalize(c.identity);
  report(key === c.key && sha256(key).slice(0, 16) === c.h16, `identity ${c.name}`, c.h16);
}

for (const name of readdirSync(new URL("lock/", vectors)).sort()) {
  const dir = new URL(`lock/${name}/.mcp/contracts/`, vectors);
  if (!existsSync(dir)) continue;
  for (const file of readdirSync(dir).sort()) {
    const text = readFileSync(new URL(file, dir)).toString("utf8");
    report(canonicalize(JSON.parse(text)) === text, `contract ${name}/${file.slice(0, 19)}`, "jcs");
  }
}

for (const name of readdirSync(new URL("lock/", vectors)).sort()) {
  const base = `lock/${name}/`;
  if (!existsSync(new URL(`${base}expected.json`, vectors))) continue;
  const expected = JSON.parse(read(`${base}expected.json`));
  const approved = Object.entries(expected.meta).filter(([, m]) => m.flag === null);
  if (approved.length === 0) continue;
  const listing = JSON.parse(read(`${base}listing.json`));
  const shards = readdirSync(new URL(`${base}.mcp/lock/`, vectors)).filter((f) => /--[0-9a-f]{16}\.json$/.test(f));
  const entries = Object.assign({}, ...shards.map((f) => JSON.parse(read(`${base}.mcp/lock/${f}`)).tools));
  for (const [tool] of approved) {
    const served = listing.tools.find((t) => t.name === tool);
    const js = metaDigest(served._meta);
    report(js === entries[tool].metaDigest, `metaDigest ${name}/${tool}`, js ?? "no digest");
  }
}

for (const name of readdirSync(new URL("lock/", vectors)).sort()) {
  const base = `lock/${name}/`;
  if (!existsSync(new URL(`${base}expected.json`, vectors))) continue;
  const { event } = JSON.parse(read(`${base}expected.json`));
  if (event === null) continue;
  const named = JSON.parse(read(`${base}listing.json`)).tools.filter(
    (t) => t !== null && typeof t === "object" && !Array.isArray(t) && typeof t.name === "string",
  );
  const ok = named.length === event.tools.length && named.every((t, i) => digest(t) === event.tools[i].served);
  report(ok, `event ${name}`, `${event.tools.length} rows`);
}

console.log(`${total - failed} of ${total} agree`);
process.exit(failed ? 1 : 0);
