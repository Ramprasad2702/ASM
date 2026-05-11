const express = require("express");
const { spawn } = require("child_process");
const path = require("path");

const app = express();
const PORT = 3000;

// Serve static files
app.use(express.static(__dirname));

// Serve results
app.use("/results", express.static(path.join(__dirname, "results")));

// Default route (FIX)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "frontend.html"));
});

// Scan route
app.get("/scan", (req, res) => {
  const target = req.query.target;

  if (!target) {
    return res.status(400).json({ error: "Target required" });
  }

  const fs = require("fs");
  const resultsDir = path.join(__dirname, "results");
  if (!fs.existsSync(resultsDir)) {
    fs.mkdirSync(resultsDir, { recursive: true });
  }

  const safeTarget = target.replace(/[^a-z0-9]/gi, "_");
  const logPath = path.join(resultsDir, `${safeTarget}.log`);
  const logFd = fs.openSync(logPath, "a");
  
  spawn("node", ["pipeline.js", target], {
    detached: true,
    stdio: ["ignore", logFd, logFd]
  }).unref();

  res.json({ status: "started", target });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
