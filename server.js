const express = require("express");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");
const PORT = process.env.PORT || 3000;

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

    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const dateStr = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}_${pad(d.getHours())}-${pad(d.getMinutes())}-${pad(d.getSeconds())}`;
    const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
    const uniqueScanId = `${safeTarget}_${dateStr}`;

    const logPath = path.join(resultsDir, `${uniqueScanId}.log`);
    const logFd = fs.openSync(logPath, "a");
    
    // Spawn the pipeline in the background with timestamp-based directories
    const child = spawn("node", ["pipeline.js", target], {
      cwd: __dirname,
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: {
        ...process.env,
        SCAN_ID: uniqueScanId,
        OUTPUT_DIR: path.join(resultsDir, uniqueScanId)
      }
    });

    child.unref();

    res.json({ status: "started", target, id: uniqueScanId });
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
              data.target = content.domain || data.target;
              data.risk = content.risk?.level || "LOW";
              data.assets = (content.recon?.assets?.urls?.length || 0) + (content.recon?.assets?.ips?.length || 0);
              data.vulns = content.findings?.length || 0;
              data.timestamp = content.__meta__?.timestamp || data.timestamp;
          } catch (e) {}
      }
      return data;
    });
    
    res.json(history.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
  });

  // Brand Scan initiation endpoint
  app.get("/scan/brand", (req, res) => {
    const brand = req.query.brand;
    const domain = req.query.domain || "";
    
    if (!brand) {
      return res.status(400).json({ error: "Brand required" });
    }

    const safeBrand = brand.replace(/[^a-z0-9.-]/gi, "_");
    const resultsDir = path.join(__dirname, "results", safeBrand);
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const outJsonPath = path.join(resultsDir, "brand.json");
    
    let args = ["brand_monitor.js", "--brand", brand, "--json-out", outJsonPath];
    if (domain) {
      args.push("--domain");
      args.push(domain);
    }

    const child = spawn("node", args, {
      cwd: __dirname,
      detached: true,
      stdio: "ignore"
    });
    child.unref();

    res.json({ status: "started", target: brand, message: "Brand intelligence scan initiated." });
  });

  // Result retrieval endpoint (for polling)
  app.get("/results/brand/:brand", (req, res) => {
    const brand = req.params.brand;
    const safeBrand = brand.replace(/[^a-z0-9.-]/gi, "_");
    const outJsonPath = path.join(__dirname, "results", safeBrand, "brand.json");

    if (fs.existsSync(outJsonPath)) {
        try {
            const report = JSON.parse(fs.readFileSync(outJsonPath, "utf-8"));
            res.json(report);
        } catch (e) {
            res.status(500).json({ error: "Failed to parse report" });
        }
    } else {
        res.status(404).json({ error: "Still scanning..." });
    }
  });


// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[SERVER] Server running at http://0.0.0.0:${PORT}`);
});
