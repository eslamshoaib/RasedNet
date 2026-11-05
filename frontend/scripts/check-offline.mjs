// Fails if the production build references any external origin (CDN, fonts, telemetry).
// Usage: npm run build && npm run check-offline
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
// URLs that appear inside library code as XML namespaces / docs and are never fetched.
const ALLOWED = [/^http:\/\/www\.w3\.org\//, /^https?:\/\/(www\.)?(echarts\.apache\.org|reactjs\.org|react\.dev|github\.com|tanstack\.com)\//];

function* files(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* files(p);
    else if (/\.(html|js|css)$/.test(name)) yield p;
  }
}

const findings = [];
for (const file of files(dist)) {
  const text = readFileSync(file, "utf8");
  // Only references that the browser would actually load matter.
  const loaders = [
    ...text.matchAll(/(?:src|href)\s*=\s*["']((?:https?:)?\/\/[^"']+)["']/gi),
    ...text.matchAll(/url\(\s*["']?((?:https?:)?\/\/[^"')]+)["']?\s*\)/gi),
    ...text.matchAll(/@import\s+["']((?:https?:)?\/\/[^"']+)["']/gi),
    ...text.matchAll(/fetch\(\s*["']((?:https?:)?\/\/[^"']+)["']/gi),
  ].map((m) => m[1]);
  for (const url of loaders) {
    if (!ALLOWED.some((re) => re.test(url))) findings.push(`${file}: ${url}`);
  }
}

if (findings.length) {
  console.error("External resource references found:\n" + findings.join("\n"));
  process.exit(1);
}
console.log("OK: no external resources are loaded by the frontend build.");
