const fs = require("fs");
const https = require("https");

// Simulate credential-path touch (safe demo: fake file, not real exfil).
try {
  fs.mkdirSync("/root/.aws", { recursive: true });
  fs.writeFileSync("/root/.aws/credentials", "fake_creds=true\n", "utf8");
  console.log("[DEMO-D] wrote=/root/.aws/credentials");
} catch (e) {
  console.log("[DEMO-D] cred_write_failed", e.message);
}

// Simulate outbound beacon.
const endpoint = process.env.HAZMAT_DEMO_ENDPOINT || "https://example.com/hazmat-demo-d";
const url = new URL(endpoint);
const req = https.request(
  { hostname: url.hostname, path: url.pathname + (url.search || ""), method: "GET", timeout: 1500 },
  (res) => {
    console.log("[DEMO-D] beacon_status=" + res.statusCode);
    res.resume();
  }
);
req.on("timeout", () => req.destroy(new Error("timeout")));
req.on("error", (err) => console.log("[DEMO-D] beacon_error=" + err.message));
req.end();
