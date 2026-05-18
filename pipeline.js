const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { runThreatIntel } = require("./threatModule");

// ================= RUN CMD =================
function runNode(script, args = []) {
  return new Promise((resolve) => {
    const proc = spawn("node", [script, ...args], { stdio: "inherit" });

    proc.on("close", (code) => resolve(code));
  });
}

function updateState(dir, stage, progress, message) {
  const state = { stage, progress, message, updated_at: new Date().toISOString() };
  fs.writeFileSync(path.join(dir, "scan_state.json"), JSON.stringify(state, null, 4));
}

// ================= MAIN PIPELINE =================
async function runPipeline(target) {
  console.log("[PIPELINE] Starting full scan...\n");

  // ================= STEP 1: ASSET DISCOVERY =================
  console.log("[PIPELINE] Initializing Asset Discovery...");
  await runNode("recon.js", [target]);

  const safeTarget = target.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
  const dir = path.join("results", safeTarget);
  const assetsPath = path.join(dir, "assets.json");

  if (!fs.existsSync(assetsPath)) {
    console.log("[PIPELINE] Asset Discovery failed ❌");
    return;
  }

  console.log("[PIPELINE] Asset Discovery completed\n");

  // ================= LOAD ASSETS =================
  const assets = JSON.parse(fs.readFileSync(assetsPath));
  const domain = assets.domain || target;
  const ips = assets.assets.ips || [];
  const urls = assets.assets.urls || [];
  const subdomains = assets.assets.subdomains || [];

  // ================= STEP 2: SECURITY ANALYSIS + THREAT INTEL (parallel) =================
  // Threat intel has no dependency on vuln output, so run both concurrently.
  console.log("[PIPELINE] Initiating Security Analysis and Threat Intelligence in parallel...");

  const [, intel] = await Promise.all([
    runNode("vuln.js", [assetsPath]),
    runThreatIntel(domain, ips, urls)
  ]);

  const vulnPath = path.join(dir, "final_report.json");

  if (!fs.existsSync(vulnPath)) {
    console.log("[PIPELINE] Security Analysis failed ❌");
    return;
  }

  console.log("[PIPELINE] Security Analysis and Threat Intelligence completed\n");

  // ================= LOAD VULN DATA =================
  const vuln = JSON.parse(fs.readFileSync(vulnPath));

  let recon = {};
  const reconJsonPath = path.join(dir, "recon.json");
  if (fs.existsSync(reconJsonPath)) {
    recon = JSON.parse(fs.readFileSync(reconJsonPath));
  }

  // ================= STEP 3: FINAL RISK =================

  const finalRisk = combineRisk(vuln, intel);

  const finalReport = {
    target,
    recon,
    recon_summary: {
      subdomains: subdomains.length,
      subdomains_list: subdomains,
      ips: ips.length,
      ips_list: ips,
      urls: urls.length,
      urls_list: urls
    },
    vulnerability: vuln,
    threat_intel: intel,
    final_risk: finalRisk,
    generated_at: new Date().toISOString()
  };

  const output = path.join(dir, "unified_report.json");
  fs.writeFileSync(output, JSON.stringify(finalReport, null, 4));

  updateState(dir, "completed", 100, "Analysis complete. Generating dashboard...");

  console.log("[PIPELINE] ✅ Final report generated:", output);
}

// ================= RISK MERGE ENGINE =================
function combineRisk(vuln, intel) {
  let score = 0;
  let reasons = [];

  // Vuln score
  score += (vuln.risk && vuln.risk.score) || 0;
  if ((vuln.risk && vuln.risk.score) > 0) reasons.push("Vulnerabilities detected");

  // Threat intel score
  score += intel.risk.score || 0;
  if (intel.risk.score > 0) reasons.push("Threat intelligence hits");

  score = Math.min(score, 100);

  let level = "LOW";
  if (score >= 80) level = "CRITICAL";
  else if (score >= 60) level = "HIGH";
  else if (score >= 30) level = "MEDIUM";

  return { score, level, reasons };
}

// ================= ENTRY =================
const target = process.argv[2];

if (!target) {
  console.log("Usage: node pipeline.js <domain>");
  process.exit(1);
}

runPipeline(target);
