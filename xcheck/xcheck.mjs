// Recompute every vector with an independent RFC 8785 implementation (npm canonicalize).
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

// SEP section 1: no digest if any number is non-finite or has magnitude >= 2^53.
const inRange = (v) =>
  typeof v === "number" ? Number.isFinite(v) && Math.abs(v) < 2 ** 53
  : Array.isArray(v) ? v.every(inRange)
  : v !== null && typeof v === "object" ? Object.values(v).every(inRange)
  : true;

const vectors = JSON.parse(readFileSync(new URL("../vectors/tools.json", import.meta.url)));
let failed = 0;
for (const v of vectors) {
  const { _meta, ...body } = v.tool;
  const js = inRange(body)
    ? "sha256:" + createHash("sha256").update(canonicalize(body), "utf8").digest("hex")
    : null;
  const ok = v.expected === js;
  if (!ok) failed++;
  console.log(`${ok ? "match   " : "MISMATCH"} ${v.name}  ${js ?? "no digest"}`);
}
console.log(`${vectors.length - failed} of ${vectors.length} agree`);
process.exit(failed ? 1 : 0);
