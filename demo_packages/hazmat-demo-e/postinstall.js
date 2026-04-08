const fs = require("fs");
const net = require("net");

try {
  fs.writeFileSync("/var/tmp/hazmat-demo-e-beacon-marker.txt", "beacon=attempt\n", "utf8");
  console.log("[DEMO-E] marker_written=/var/tmp/hazmat-demo-e-beacon-marker.txt");
} catch (e) {
  console.log("[DEMO-E] marker_write_failed", e.message);
}

// Unusual outbound port attempt (safe demo: connect will likely fail).
const host = process.env.HAZMAT_DEMO_HOST || "example.com";
const port = Number(process.env.HAZMAT_DEMO_PORT || "1337");
const sock = net.createConnection({ host, port, timeout: 1200 }, () => {
  console.log("[DEMO-E] connected=" + host + ":" + port);
  sock.end();
});
sock.on("timeout", () => sock.destroy(new Error("timeout")));
sock.on("error", (err) => console.log("[DEMO-E] connect_error=" + err.message));
