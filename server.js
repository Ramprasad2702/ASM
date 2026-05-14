const express = require("express");
const { spawn } = require("child_process");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

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

  const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
  const logPath = path.join(resultsDir, `${safeTarget}.log`);
  const logFd = fs.openSync(logPath, "a");
  
  spawn("node", ["pipeline.js", target], {
    detached: true,
    stdio: ["ignore", logFd, logFd]
  }).unref();

  res.json({ status: "started", target });
});

// Assets endpoint
app.get("/assets", (req, res) => {
  const target = req.query.target;
  if (!target) {
    return res.status(400).json({ error: "Target required" });
  }

  const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
  const reconPath = path.join(__dirname, "results", safeTarget, "recon.json");

  const fs = require("fs");
  if (fs.existsSync(reconPath)) {
    res.sendFile(reconPath);
  } else {
    res.status(404).json({ error: "Recon results not found for this target. Recon might still be running." });
  }
});

// Scan History endpoint
app.get("/scans", (req, res) => {
  const fs = require("fs");
  const resultsDir = path.join(__dirname, "results");
  if (!fs.existsSync(resultsDir)) return res.json([]);
  
  const folders = fs.readdirSync(resultsDir).filter(f => {
    return fs.statSync(path.join(resultsDir, f)).isDirectory();
  });
  
  const history = folders.map(f => {
    const reportPath = path.join(resultsDir, f, "unified_report.json");
    const stats = fs.statSync(path.join(resultsDir, f));
    let data = { target: f, id: f, timestamp: stats.mtime };
    
    if (fs.existsSync(reportPath)) {
        try {
            const report = JSON.parse(fs.readFileSync(reportPath));
            data.target = report.target || data.target;
            data.risk = report.final_risk?.level || "UNKNOWN";
            data.assets = (report.recon_summary?.urls || 0) + (report.recon_summary?.ips || 0);
            data.vulns = report.vulnerability?.findings?.length || 0;
            data.timestamp = report.generated_at || data.timestamp;
        } catch(e) {}
    }
    return data;
  });
  
  res.json(history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
