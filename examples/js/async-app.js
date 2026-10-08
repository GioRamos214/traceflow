// Plain JavaScript (ES module) exercising arrow functions and async/await.

const double = (x) => x * 2;

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchValue(id) {
  await delay(5);
  return { id, value: double(id) };
}

async function main() {
  const results = [];
  for (const id of [1, 2, 3]) {
    const r = await fetchValue(id);
    results.push(r.value);
  }
  console.log("results:", results.join(", "));
}

main();
