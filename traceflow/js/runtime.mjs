// The recording runtime, installed as globalThis.__traceflow__ before the program
// runs. The instrumented code calls enter/leave/throw; this builds the same trace
// structure the Python tracer produces, so traceflow's viewer renders it unchanged.

const now = () => process.hrtime.bigint();

export class Runtime {
  constructor({ root, maxCalls = 250000 } = {}) {
    this.root = root;
    this.maxCalls = maxCalls;
    this.calls = [];
    this.events = [];
    this.sources = {};        // key -> {file, start, name, lines}
    this.files = new Map();   // fileId -> {path, lines: [names...]}
    this.truncated = false;
    this.openIds = new Set();
    this.closedLog = [];
    this.stack = [];
    this.t0 = now();
    this.ctl = null;          // set in live mode
  }

  nowNs() { return Number(now() - this.t0); }

  registerFile(fileId, path, source, fnLines) {
    this.files.set(fileId, { path, source, fnLines });
  }

  _sourceKey(file, line, name) {
    const key = `${file}:${line}:${name}`;
    if (!(key in this.sources)) {
      const f = [...this.files.values()].find((x) => x.path === file);
      const allLines = f ? f.source.split("\n") : [];
      // record the whole file for <module>, otherwise the function's own span isn't known
      // cheaply here, so keep the full file and let the viewer window it
      this.sources[key] = { file, start: 1, name, lines: allLines.map((l) => l.replace(/\r$/, "")) };
    }
    return key;
  }

  _event(type, call, extra) {
    this.events.push({ seq: this.events.length, t: this.nowNs(), type, call, ...(extra || {}) });
  }

  enter(meta, args) {
    if (this.calls.length >= this.maxCalls) { this.truncated = true; this._noRecord = (this._noRecord || 0) + 1; this.stack.push(null); return; }
    const parent = this.stack.length ? this.stack[this.stack.length - 1] : null;
    const id = this.calls.length;
    const file = this.files.get(meta.f)?.path ?? null;
    const parentRec = parent != null ? this.calls[parent] : null;
    const rec = {
      id, parent, depth: parentRec ? parentRec.depth + 1 : 0, kind: meta.k || "js", thread: 0,
      name: meta.n, qualname: meta.n, module: null, file, def_line: meta.l,
      source: file ? this._sourceKey(file, meta.l, meta.n) : null,
      caller_file: parentRec ? parentRec.file : null, caller_line: this._lastCallLine ?? null,
      caller_name: parentRec ? parentRec.qualname : null,
      start: this.nowNs(), end: null, status: "running",
      args: args ? mapRepr(args) : null, return: null, exception: null, handled: [],
      children: [], lines: {}, arcs: [],
    };
    this.calls.push(rec);
    this.openIds.add(id);
    if (parentRec) parentRec.children.push(id);
    this.stack.push(id);
    this._event("call", id);
    if (this.ctl && this.ctl.active) this.ctl.onCall(rec, meta);
  }

  ret(value) {
    // called just before a `return`; remember the value for the leave() in the finally block
    const id = this.stack.length ? this.stack[this.stack.length - 1] : null;
    if (id != null) { const rec = this.calls[id]; rec.return = safeRepr(value); rec._returned = true; }
    return value;
  }

  evalArg(value) {
    // called with the argument of a direct eval(...); lets the security monitor see the code
    if (this.onEval) { try { this.onEval(value); } catch {} }
    return value;
  }

  leave() {
    const id = this.stack.pop();
    if (id == null) return;
    const rec = this.calls[id];
    if (rec.status === "running") {
      rec.end = this.nowNs();
      rec.status = "returned";
      if (!rec._returned) rec.return = "undefined";
      this.openIds.delete(id);
      this.closedLog.push(id);
      this._event("return", id);
    }
  }

  throw(err) {
    const id = this.stack.length ? this.stack[this.stack.length - 1] : null;
    if (id == null) return;
    const rec = this.calls[id];
    if (rec.status !== "running") return;
    rec.end = this.nowNs();
    rec.status = "raised";
    rec.exception = { type: err && err.name ? String(err.name) : "Error", message: safeRepr(err && err.message != null ? String(err.message) : String(err)), line: rec.def_line };
    this.openIds.delete(id);
    this.closedLog.push(id);
    this._event("raise", id);
  }

  recordIO(kind, text) {
    const id = this.stack.length ? this.stack[this.stack.length - 1] : null;
    this._event(kind, id, { text });
  }

  finish(meta) {
    for (const rec of this.calls) {
      if (rec.end == null) { rec.end = this.nowNs(); rec.status = "unfinished"; }
    }
    return {
      format: "traceflow-trace/1",
      meta: { ...meta, duration_ns: this.nowNs(), truncated: this.truncated, call_count: this.calls.length },
      calls: this.calls, events: this.events, sources: this.sources,
    };
  }
}

function mapRepr(obj) {
  const out = {};
  for (const k of Object.keys(obj)) out[k] = safeRepr(obj[k]);
  return out;
}

export function safeRepr(v, depth = 0) {
  try {
    if (v === null) return "null";
    if (v === undefined) return "undefined";
    const t = typeof v;
    if (t === "string") return JSON.stringify(v.length > 120 ? v.slice(0, 120) + "…" : v);
    if (t === "number" || t === "boolean" || t === "bigint") return String(v) + (t === "bigint" ? "n" : "");
    if (t === "symbol") return v.toString();
    if (t === "function") return `[Function ${v.name || "anonymous"}]`;
    if (Array.isArray(v)) {
      if (depth >= 2) return "[…]";
      const items = v.slice(0, 8).map((x) => safeRepr(x, depth + 1));
      return "[" + items.join(", ") + (v.length > 8 ? ", …" : "") + "]";
    }
    if (t === "object") {
      const name = v.constructor && v.constructor.name;
      if (name && name !== "Object") return reprObject(v, depth, name + " ");
      return reprObject(v, depth, "");
    }
    return String(v);
  } catch {
    return "<unrepresentable>";
  }
}

function reprObject(v, depth, prefix) {
  if (depth >= 2) return prefix + "{…}";
  const keys = Object.keys(v).slice(0, 8);
  const parts = keys.map((k) => `${k}: ${safeRepr(v[k], depth + 1)}`);
  return prefix + "{" + parts.join(", ") + (Object.keys(v).length > 8 ? ", …" : "") + "}";
}
