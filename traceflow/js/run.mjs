// traceflow JavaScript/TypeScript recorder entry point.
//   node traceflow/js/run.mjs --root <dir> --out <file.json> [--meta <json>] -- <script> [args...]
// Installs the runtime, hooks module loading to instrument user code (and strip TS
// types), runs the target, and writes a trace JSON in traceflow's format.

import { registerHooks, stripTypeScriptTypes } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import path from "node:path";
import { Runtime } from "./runtime.mjs";

let instrument;
try {
  ({ instrument } = await import("./instrument.mjs"));
} catch (e) {
  if (e && e.code === "ERR_MODULE_NOT_FOUND") {
    console.error("traceflow: the Node recorder needs its dependency 'acorn'. Run:\n" +
      "  npm install --prefix " + path.dirname(fileURLToPath(import.meta.url)));
    process.exit(2);
  }
  throw e;
}

function parseArgs(argv) {
  const o = { root: process.cwd(), out: null, meta: {}, script: null, args: [], security: false };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") { o.script = argv[++i]; o.args = argv.slice(i + 1); break; }
    else if (a === "--root") o.root = path.resolve(argv[++i]);
    else if (a === "--out") o.out = argv[++i];
    else if (a === "--meta") o.meta = JSON.parse(argv[++i]);
    else if (a === "--security") o.security = true;
    else if (o.script == null) { o.script = a; o.args = argv.slice(i + 1); break; }
  }
  return o;
}

const opts = parseArgs(process.argv.slice(2));
if (!opts.script) { console.error("traceflow js: no script given"); process.exit(2); }
const scriptPath = path.resolve(opts.script);
const rootNC = path.normalize(opts.root).toLowerCase();

const rt = new Runtime({ root: opts.root });
globalThis.__traceflow__ = rt;

let nextFileId = 0;
const fileIds = new Map();

const NM = `${path.sep}node_modules${path.sep}`;
const loadedPackages = new Map(); // name -> {name, version, modules, called}
const loaderFiles = new Set();    // normalized lowercase paths the module loader read (not program activity)

const SELF_DIR = path.dirname(fileURLToPath(import.meta.url)).toLowerCase(); // traceflow/js — never instrument our own recorder

const isUserFile = (p) => {
  if (!p) return false;
  const n = path.normalize(p).toLowerCase();
  if (n.includes(NM) || n.startsWith(SELF_DIR + path.sep)) return false;
  return n.startsWith(rootNC + path.sep) || n === path.normalize(scriptPath).toLowerCase();
};

function notePackage(filePath) {
  // record a third-party package when one of its files is loaded, with its version
  const idx = filePath.toLowerCase().lastIndexOf(NM.toLowerCase());
  if (idx < 0) return;
  const after = filePath.slice(idx + NM.length);
  const parts = after.split(/[\\/]/);
  const name = parts[0] && parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
  if (!name || loadedPackages.has(name)) return;
  let version = null, pkgDir = filePath.slice(0, idx + NM.length) + name;
  try { version = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8")).version; } catch {}
  loadedPackages.set(name, { name, version: version || "unknown", modules: [name], called: true });
}

const TS_FORMATS = { "module-typescript": "module", "commonjs-typescript": "commonjs" };

registerHooks({
  load(url, context, nextLoad) {
    if (!url.startsWith("file:")) return nextLoad(url, context);
    let filePath;
    try { filePath = fileURLToPath(url); } catch { return nextLoad(url, context); }
    if (filePath.includes(NM)) { try { notePackage(filePath); } catch {} ; return nextLoad(url, context); }
    if (!isUserFile(filePath)) return nextLoad(url, context);

    const result = nextLoad(url, { ...context, format: context.format });
    let format = result.format;
    let source = result.source == null ? readFileSync(filePath, "utf8") : String(result.source);

    if (format in TS_FORMATS || /\.(ts|mts|cts)$/.test(filePath)) {
      source = stripTypeScriptTypes(source, { mode: "strip" }); // preserves line numbers
      format = TS_FORMATS[format] || (/\.cts$/.test(filePath) ? "commonjs" : "module");
    }
    if (format !== "module" && format !== "commonjs") return { ...result, source, format };

    loaderFiles.add(path.normalize(filePath).toLowerCase());
    let fileId = fileIds.get(filePath);
    if (fileId == null) { fileId = nextFileId++; fileIds.set(filePath, fileId); }
    const res = instrument(source, { file: filePath, fileId });
    if (res) { source = res.code; }
    rt.registerFile(fileId, filePath, result.source == null ? readFileSync(filePath, "utf8") : stripForSource(filePath, result.source), null);
    return { source, format, shortCircuit: true };
  },
});

function stripForSource(filePath, original) {
  // the viewer shows the *original* source (with types), so keep it untouched
  try { return readFileSync(filePath, "utf8"); } catch { return String(original); }
}

// capture stdout / stderr, tag each write to the running call
for (const [name, stream] of [["stdout", process.stdout], ["stderr", process.stderr]]) {
  const orig = stream.write.bind(stream);
  stream.write = (chunk, enc, cb) => {
    try { rt.recordIO(name, Buffer.isBuffer(chunk) ? chunk.toString() : String(chunk)); } catch {}
    return orig(chunk, enc, cb);
  };
}

let monitor = null;
if (opts.security) {
  const { SecurityMonitor } = await import("./security.mjs");
  monitor = new SecurityMonitor(rt);
  rt.onEval = (code) => monitor.recordEval(code);
  // the module loader reads source files via fs; don't report those as program activity
  monitor.isLoaderRead = (p) => {
    const n = path.normalize(p).toLowerCase();
    return n.includes(NM) || n === path.normalize(scriptPath).toLowerCase() || loaderFiles.has(n);
  };
  monitor.start();
}

const meta = {
  script: scriptPath, argv: opts.args, root: opts.root,
  python: process.version, lang: "javascript",
  recorded_at: new Date().toISOString().slice(0, 19),
  exit_status: 0, error: null, ...opts.meta,
};

function writeTrace(exitStatus, error) {
  meta.exit_status = exitStatus;
  if (error) meta.error = error;
  const trace = rt.finish(meta);
  if (monitor) {
    monitor.stop();
    const r = monitor.report();
    trace.security_raw = { ...r, packages: [...loadedPackages.values()] };
  }
  if (opts.out) writeFileSync(opts.out, JSON.stringify(trace));
}

process.on("uncaughtException", (err) => {
  writeTrace(1, `${err && err.name ? err.name : "Error"}: ${err && err.message ? err.message : err}`);
  process.stderr.write(String(err && err.stack ? err.stack : err) + "\n");
  process.exit(1);
});
process.on("exit", () => { if (!globalThis.__tf_written__) { globalThis.__tf_written__ = true; writeTrace(process.exitCode || 0, null); } });

const require = createRequire(path.join(opts.root, "package.json"));
const targetUrl = pathToFileURL(scriptPath).href;
process.argv = [process.argv[0], scriptPath, ...opts.args];
await import(targetUrl);
