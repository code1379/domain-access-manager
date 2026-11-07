import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const source = readFileSync("_worker.js", "utf8");
const pageStart = source.indexOf("const PAGE = `");
if (pageStart < 0) throw new Error("PAGE template not found");
const contentStart = pageStart + "const PAGE = `".length;
const pageEnd = source.indexOf("`;\n\nexport default", contentStart);
if (pageEnd < 0) throw new Error("PAGE template end not found");
const page = source.slice(contentStart, pageEnd);
const scriptStart = page.indexOf("<script>");
const scriptEnd = page.indexOf("</script>", scriptStart);
if (scriptStart < 0 || scriptEnd < 0) throw new Error("Embedded page script not found");
const script = page.slice(scriptStart + "<script>".length, scriptEnd);
const path = join(tmpdir(), "domain-access-manager-page-check-" + process.pid + ".mjs");
try {
  writeFileSync(path, script);
  const result = spawnSync(process.execPath, ["--check", path], { encoding: "utf8" });
  if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || "Embedded page script syntax check failed\n");
    process.exit(result.status || 1);
  }
  process.stdout.write("Embedded page script syntax OK\n");
} finally {
  try { unlinkSync(path); } catch {}
}
