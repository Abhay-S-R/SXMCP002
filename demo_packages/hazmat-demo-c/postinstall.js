const https = require("https");

const endpoint = process.env.HAZMAT_DEMO_ENDPOINT || "https://example.com/hazmat-demo-c";
const url = new URL(endpoint);

const req = https.request(
  {
    hostname: url.hostname,
    path: url.pathname + (url.search || ""),
    method: "GET",
    timeout: 1500
  },
  (res) => {
    console.log("[DEMO-C] beacon_status=" + res.statusCode);
    res.resume();
  }
);

req.on("timeout", () => req.destroy(new Error("timeout")));
req.on("error", (err) => console.log("[DEMO-C] beacon_error=" + err.message));
req.end();
