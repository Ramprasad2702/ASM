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

// ================= MAIN PIPELINE =================
async function runPipeline(target) {
  console.log("[PIPELINE] Starting full scan...\n");

  // ================= STEP 1: RECON =================
  console.log("[PIPELINE] Recon started");
  await runNode("recon.js", [target]);

  const safeTarget = target.replace(/[^a-z0-9]/gi, "_");
  const dir = path.join("results", safeTarget);
  const assetsPath = path.join(dir, "assets.json");

  if (!fs.existsSync(assetsPath)) {
    console.log("[PIPELINE] Recon failed ❌");
    return;
  }

  console.log("[PIPELINE] Recon completed\n");

  // ================= STEP 2: VULN =================
  console.log("[PIPELINE] Vulnerability scan started");
  await runNode("vuln.js", [assetsPath]);

  const vulnPath = path.join(dir, "final_report.json");

  if (!fs.existsSync(vulnPath)) {
    console.log("[PIPELINE] Vuln scan failed ❌");
    return;
  }

  console.log("[PIPELINE] Vulnerability scan completed\n");

  // ================= LOAD DATA =================
  const assets = JSON.parse(fs.readFileSync(assetsPath));
  const vuln = JSON.parse(fs.readFileSync(vulnPath));

  const domain = assets.domain || target;
  const ips = assets.assets.ips || [];
  const urls = assets.assets.urls || [];

  // ================= STEP 3: THREAT INTEL =================
  console.log("[PIPELINE] Threat intelligence started");

  const intel = await runThreatIntel(domain, ips, urls);

  console.log("[PIPELINE] Threat intelligence completed\n");

  // ================= STEP 4: FINAL RISK =================

  const finalRisk = combineRisk(vuln, intel);

  const finalReport = {
    target,
    recon_summary: {
      ips: ips.length,
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
