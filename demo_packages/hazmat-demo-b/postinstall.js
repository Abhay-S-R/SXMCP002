const fs = require("fs");

try {
  fs.writeFileSync("/tmp/hazmat-demo-b-marker.txt", "marker=true\n", "utf8");
  console.log("[DEMO-B] marker_written=/tmp/hazmat-demo-b-marker.txt");
} catch (e) {
  console.log("[DEMO-B] marker_write_failed", e.message);
}
