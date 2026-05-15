const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const cluster = require("cluster");
const os = require("os");

const PORT = process.env.PORT || 3000;

if (cluster.isPrimary) {
  const numCPUs = os.cpus().length;
  console.log(`[MASTER] Master process ${process.pid} is running`);
  console.log(`[MASTER] Forking ${numCPUs} workers...`);

  // Fork workers.
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  cluster.on("exit", (worker, code, signal) => {
    console.log(`[MASTER] Worker ${worker.process.pid} died. Forking a new one...`);
    cluster.fork();
  });
} else {
  const app = express();

  // Serve static files
  app.use(express.static(__dirname));

  // Serve results
  app.use("/results", express.static(path.join(__dirname, "results")));

  // Default route
  app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "frontend.html"));
  });

  // Scan initiation endpoint
  app.get("/scan", (req, res) => {
    const target = req.query.target;
    if (!target) {
      return res.status(400).json({ error: "Target required" });
    }

    const resultsDir = path.join(__dirname, "results");
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
    const logPath = path.join(resultsDir, `${safeTarget}.log`);
    const logFd = fs.openSync(logPath, "a");
    
    // Spawn the pipeline in the background
    const child = spawn("node", ["pipeline.js", target], {
      detached: true,
      stdio: ["ignore", logFd, logFd]
    });

    child.unref();

    res.json({ status: "started", target, id: safeTarget });
  });

  // Assets endpoint
  app.get("/assets", (req, res) => {
    const target = req.query.target;
    if (!target) {
      return res.status(400).json({ error: "Target required" });
    }

    const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
    const reconPath = path.join(__dirname, "results", safeTarget, "recon.json");

    if (fs.existsSync(reconPath)) {
      res.sendFile(reconPath);
    } else {
      res.status(404).json({ error: "Recon results not found for this target. Recon might still be running." });
    }
  });

  // Threat Intel endpoint
  app.get("/threat", (req, res) => {
    const target = req.query.target;
    if (!target) {
      return res.status(400).json({ error: "Target required" });
    }

    const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
    const reportPath = path.join(__dirname, "results", safeTarget, "unified_report.json");

    if (fs.existsSync(reportPath)) {
      try {
        const report = JSON.parse(fs.readFileSync(reportPath));
        res.json(report.threat_intel || {});
      } catch (e) {
        res.status(500).json({ error: "Failed to parse report" });
      }
    } else {
      res.status(404).json({ error: "Threat intelligence not found for this target." });
    }
  });

  // Scan History endpoint
  app.get("/scans", (req, res) => {
    const resultsDir = path.join(__dirname, "results");
    if (!fs.existsSync(resultsDir)) {
      return res.json([]);
    }

    const folders = fs.readdirSync(resultsDir).filter(f => fs.statSync(path.join(resultsDir, f)).isDirectory());

    const history = folders.map(f => {
      const reportPath = path.join(resultsDir, f, "unified_report.json");
      const stats = fs.statSync(path.join(resultsDir, f));
      let data = { target: f, id: f, timestamp: stats.mtime };
      
      if (fs.existsSync(reportPath)) {
          try {
              const content = JSON.parse(fs.readFileSync(reportPath));
              data.target = content.target || data.target;
              data.risk = content.final_risk?.level || "UNKNOWN";
              data.assets = (content.recon_summary?.urls || 0) + (content.recon_summary?.ips || 0);
              data.vulns = content.vulnerability?.findings?.length || 0;
              data.timestamp = content.generated_at || data.timestamp;
          } catch (e) {}
      }
      return data;
    });
    
    res.json(history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
  });

  // Start server
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[WORKER ${process.pid}] Server running at http://0.0.0.0:${PORT}`);
  });
}
