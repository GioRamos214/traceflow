// Rewrites a source file with acorn so every function reports when it is entered
// and when it returns or throws. The added code refers to a single global runtime
// (globalThis.__traceflow__); nothing else about the program changes, and every
// inserted construct is one physical line so the original line numbers are preserved.

import { Parser } from "acorn";

const RT = "globalThis.__traceflow__";

// Walk the AST and collect the edits to make, as {pos, text} insertions, then apply
// them back-to-front so earlier positions stay valid.
export function instrument(code, { file, fileId }) {
  let ast;
  try {
    ast = Parser.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true, allowAwaitOutsideFunction: true, allowReturnOutsideFunction: true });
  } catch {
    return null; // leave unparseable files untouched
  }
  const edits = [];
  let fnSeq = 0;

  const funcInfo = (node, kind) => {
    const name = functionName(node) || "(anonymous)";
    const line = node.loc.start.line;
    const id = fnSeq++;
    return { id, name, line, kind, meta: `{i:${id},n:${JSON.stringify(name)},l:${line},f:${fileId}}` };
  };

  const enterText = (info, node) => {
    const params = node.params
      .map((p) => paramName(p))
      .filter(Boolean);
    const argExpr = params.length ? `{${params.map((n) => `${JSON.stringify(n)}:(typeof ${n}==="undefined"?undefined:${n})`).join(",")}}` : "null";
    return `${RT}.enter(${info.meta},${argExpr});try{`;
  };
  const leaveText = () => `}catch(__tf_e){${RT}.throw(__tf_e);throw __tf_e;}finally{${RT}.leave();}`;

  // `order` breaks ties when two edits share a position (e.g. an empty `{}` body):
  // openers (0) end up left of closers (2), so the result is `{ enter … leave }`.
  const wrapBlockBody = (node, info) => {
    const body = node.body;
    edits.push({ pos: body.start + 1, order: 0, text: enterText(info, node) });
    edits.push({ pos: body.end - 1, order: 2, text: leaveText() });
  };

  const wrapExpressionBody = (node, info) => {
    // arrow with expression body: () => expr  ->  () => { ...enter; try { return __rt.ret(expr) } ... }
    const b = node.body;
    edits.push({ pos: b.start, order: 0, text: `{${enterText(info, node)}return ${RT}.ret(` });
    edits.push({ pos: b.end, order: 2, text: `);${leaveText()}}` });
  };

  const handleFunction = (node, kind) => {
    const info = funcInfo(node, kind);
    if (node.body.type === "BlockStatement") wrapBlockBody(node, info);
    else wrapExpressionBody(node, info);
  };

  walk(ast, {
    FunctionDeclaration: (n) => handleFunction(n, "function"),
    FunctionExpression: (n) => handleFunction(n, "function"),
    ArrowFunctionExpression: (n) => handleFunction(n, "arrow"),
    // record the returned value; ret(v) returns v. (`return;` has no argument, so it stays undefined)
    ReturnStatement: (n) => {
      if (n.argument && n.argument.start != null) {
        edits.push({ pos: n.argument.start, text: `${RT}.ret(` });
        edits.push({ pos: n.argument.end, text: `)` });
      }
    },
    // record the argument to a direct eval(...) call (a security sink); evalArg(v) returns v
    CallExpression: (n) => {
      if (n.callee.type === "Identifier" && n.callee.name === "eval" && n.arguments.length === 1
          && n.arguments[0].start != null) {
        edits.push({ pos: n.arguments[0].start, text: `${RT}.evalArg(` });
        edits.push({ pos: n.arguments[0].end, text: `)` });
      }
    },
  });

  if (!edits.length) return { code, functions: fnSeq };
  edits.sort((a, b) => b.pos - a.pos || (b.order ?? 1) - (a.order ?? 1));
  let out = code;
  for (const e of edits) out = out.slice(0, e.pos) + e.text + out.slice(e.pos);
  return { code: out, functions: fnSeq };
}

function functionName(node) {
  if (node.id && node.id.name) return node.id.name;
  const p = node._tfParent;
  if (p) {
    if (p.type === "VariableDeclarator" && p.id.type === "Identifier") return p.id.name;
    if (p.type === "AssignmentExpression" && p.left.type === "Identifier") return p.left.name;
    if (p.type === "Property" && p.key) return p.key.name || p.key.value;
    if (p.type === "MethodDefinition" && p.key) return (p.static ? "static " : "") + (p.key.name || p.key.value);
    if (p.type === "PropertyDefinition" && p.key) return p.key.name || p.key.value;
  }
  return null;
}

function paramName(p) {
  if (p.type === "Identifier") return p.name;
  if (p.type === "AssignmentPattern" && p.left.type === "Identifier") return p.left.name;
  if (p.type === "RestElement" && p.argument.type === "Identifier") return p.argument.name;
  return null; // destructured params: skip, they have no single binding name
}

// Minimal AST walk that records each node's parent (for naming) and dispatches by type.
function walk(node, visitors, parent = null) {
  if (!node || typeof node.type !== "string") return;
  node._tfParent = parent;
  const v = visitors[node.type];
  if (v) v(node);
  for (const key of Object.keys(node)) {
    if (key === "_tfParent" || key === "loc" || key === "start" || key === "end") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const c of child) if (c && typeof c.type === "string") walk(c, visitors, node);
    } else if (child && typeof child.type === "string") {
      walk(child, visitors, node);
    }
  }
}
