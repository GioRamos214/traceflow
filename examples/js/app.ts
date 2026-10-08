// A small TypeScript program to exercise the traceflow Node recorder:
// nested calls, a branch, a loop, and a caught exception.

interface Host {
  name: string;
  open: boolean;
}

function probe(name: string): Host {
  if (name === "bad-host") {
    throw new Error(`not a valid host: ${name}`);
  }
  return { name, open: name.endsWith("1") };
}

function scan(names: string[]): Record<string, string> {
  const results: Record<string, string> = {};
  for (const name of names) {
    try {
      const host = probe(name);
      results[name] = host.open ? "open" : "closed";
    } catch (e) {
      results[name] = `error: ${(e as Error).message}`;
    }
  }
  return results;
}

function main(): void {
  console.log("Scanning hosts...");
  const results = scan(["10.0.0.1", "10.0.0.2", "bad-host"]);
  console.log(JSON.stringify(results, null, 2));
}

main();
