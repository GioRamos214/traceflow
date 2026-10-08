// A deliberately insecure Node.js program for `traceflow run --security`.
// Nothing here is real: the AWS key is Amazon's documented example value, the
// secrets are fake, and the "network" call goes to a port on 127.0.0.1.
//
//   traceflow run --security examples/js-insecure/app.js "bad-host; whoami" "2+2"
//
// The two arguments stand in for untrusted user input (a host name and an
// expression), so command and code injection are detected.

const fs = require("node:fs");
const crypto = require("node:crypto");
const { execSync } = require("node:child_process");
const https = require("node:https");
const path = require("node:path");
const minimist = require("minimist");

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // hard-coded credential

function loadSettings() {
  // read a .env file (sensitive file access) into process.env
  const file = path.join(__dirname, ".env");
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    if (line && !line.startsWith("#")) {
      const [k, v] = line.split("=");
      process.env[k] = v;
    }
  }
  console.log("Loaded settings, token:", process.env.DEMO_API_TOKEN); // secret printed
}

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex"); // weak hash
}

function renderProfile(name) {
  return `<h1>Welcome, ${name}</h1>`; // XSS: not escaped
}

function ping(host) {
  return execSync(`echo pinging ${host}`).toString(); // command injection
}

function calculate(expr) {
  return eval(expr); // code injection
}

function checkStatus(token) {
  const req = https.request(
    { hostname: "127.0.0.1", port: 9, path: `/status?token=${token}`, rejectUnauthorized: false }, // TLS off + secret in URL
    () => {},
  );
  req.on("error", () => {});
  req.end();
}

function main() {
  const args = minimist(process.argv.slice(2));
  const host = process.argv[2] || "localhost";
  const expr = process.argv[3] || "1+1";

  loadSettings();
  console.log("hash:", hashPassword("password"));
  console.log(renderProfile(host));
  try {
    console.log("ping:", ping(host).trim());
  } catch (e) {
    console.log("ping failed");
  }
  try {
    console.log("calc:", calculate(expr));
  } catch (e) {
    console.log("calc failed");
  }
  checkStatus(process.env.DEMO_API_TOKEN || "tok_demo");
}

main();
