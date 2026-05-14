#!/usr/bin/env node

const { execSync, spawn } = require("child_process");
const fs = require("fs");
const dns = require("dns").promises;
const axios = require("axios");
const path = require("path");

// ===== OPTIONAL: structured WHOIS =====
let whoisJson;
try {
  whoisJson = require("whois-json");
} catch {
  whoisJson = null;
}

// ================= GLOBAL ERROR HANDLING =================
process.on("uncaughtException", (err) => {
  console.error("[FATAL] Uncaught Exception:");
  console.error(err.stack || err.message);
  writeFatalError(err);
});

process.on("unhandledRejection", (reason) => {
  console.error("[FATAL] Unhandled Promise Rejection:");
  console.error(reason);
  writeFatalError(reason);
});

// ================= CONFIG =================
const SUBFINDER_TIMEOUT = 90000;
const HTTP_TIMEOUT = 5000;

// ================= LOGGER =================
const log = {
  info: (msg) => console.log(`[INFO] ${msg}`),
  warn: (msg) => console.warn(`[WARN] ${msg}`),
  error: (msg) => console.error(`[ERROR] ${msg}`),
  cmd: (msg) => {
    // Redact tool names from command log for anonymity
    const redacted = msg.replace(/(subfinder|assetfinder|httpx-toolkit|whatweb|dig|nmap|nuclei|nikto|openssl|whois)/gi, "engine");
    console.log(`[CMD] Running specialized module: ${redacted}`);
  }
};

// ================= ERROR WRITER =================
function writeFatalError(err) {
  const errorReport = {
    status: "failed",
    error: {
      message: err.message || String(err),
      stack: err.stack || null,
      timestamp: new Date().toISOString()
    }
  };

  try {
    fs.writeFileSync("error.json", JSON.stringify(errorReport, null, 4));
  } catch { }

  process.exit(1);
}

const STATE_FILE = "scan_state.json";
function atomicWrite(file, data) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 4));
  fs.renameSync(tmp, file);
}

function updateState(dir, stage, progress, message) {
  atomicWrite(path.join(dir, STATE_FILE), {
    stage,
    progress,
    message,
    timestamp: new Date().toISOString()
  });
}

// ================= CMD =================
function runCmd(cmd, timeout = 30000) {
  log.cmd(cmd);

  try {
    return execSync(cmd, { timeout }).toString().trim();
  } catch (err) {
    return {
      error: true,
      message: err.message,
      cmd
    };
  }
}

// ================= TOOL VALIDATION =================
function checkTool(tool) {
  const res = runCmd(`which ${tool}`);
  if (!res || res.error) {
    log.error(`Required module is missing`);
    return false;
  }
  log.info(`Module validated`);
  return true;
}

// ================= UTILS =================
function extractDomain(input) {
  try {
    const url = new URL(input.includes("http") ? input : `http://${input}`);
    return url.hostname;
  } catch {
    return input;
  }
}

async function reverseDns(ip) {
  try {
    const hostnames = await dns.reverse(ip);
    log.info(`Reverse DNS resolved ${ip} to ${hostnames[0]}`);
    return hostnames[0];
  } catch (err) {
    log.warn(`Reverse DNS failed for ${ip}: ${err.message}`);
    return null;
  }
}

// ================= DNS =================
async function resolveDomain(domain) {
  try {
    const addresses = await dns.resolve4(domain);
    if (addresses && addresses.length > 0) {
      return addresses[0];
    }
    return null;
  } catch (err) {
    // Fallback to lookup for some environments
    try {
      const res = await dns.lookup(domain);
      return res.address;
    } catch {
      log.warn(`DNS failed for ${domain}: ${err.code || err.message}`);
      return null;
    }
  }
}

// ================= HTTP =================
async function httpLiveness(domain) {
  const urls = [];

  for (let scheme of ["https", "http"]) {
    try {
      const res = await axios.head(`${scheme}://${domain}`, {
        timeout: HTTP_TIMEOUT,
        maxRedirects: 5,
        validateStatus: () => true
      });

      if (res.status < 500) {
        urls.push(`${scheme}://${domain}`);
      }
    } catch { }
  }

  return urls;
}

// ================= PRIMARY DISCOVERY =================
function primaryDiscovery(domain) {
  log.info("Starting subdomain discovery...");

  if (!checkTool("subfinder")) return [];

  const out = runCmd(`subfinder -d ${domain} -silent`, SUBFINDER_TIMEOUT);

  if (!out || out.error) {
    log.warn("Primary discovery module returned no data");
    return [];
  }

  const subs = [...new Set(out.split("\n").map(s => s.trim()).filter(Boolean))];
  log.info(`Discovery module found: ${subs.length}`);

  return subs;
}

// ================= SECONDARY DISCOVERY =================
function secondaryDiscovery(domain) {
  log.info("Expanding discovery reach...");

  if (!checkTool("assetfinder")) return [];

  const out = runCmd(`assetfinder --subs-only ${domain}`, 30000);

  if (!out || out.error) {
    log.warn("Secondary discovery returned no data");
    return [];
  }

  const subs = [...new Set(out.split("\n").map(s => s.trim()).filter(Boolean))];
  log.info(`Secondary module found: ${subs.length}`);

  return subs;
}

// ================= DIG =================
function digRecords(domain) {
  if (!checkTool("dig")) return {};

  const records = {};
  const types = ["A", "AAAA", "MX", "TXT", "CNAME", "NS"];

  for (let type of types) {
    const out = runCmd(`dig ${domain} ${type} +short`);

    if (!out || out.error) {
      log.warn(`Module failed for ${type}`);
      continue;
    } else {
      records[type] = out.split("\n");
    }
  }

  return records;
}

// ================= WHOIS =================
async function whoisLookup(domain) {
  if (whoisJson) {
    try {
      return await whoisJson(domain);
    } catch (err) {
      log.warn("Structured WHOIS failed, fallback to CLI");
    }
  }

  if (!checkTool("whois")) return { error: "whois_not_available" };

  const out = runCmd(`whois ${domain}`);

  if (!out || out.error) {
    log.error(`WHOIS command failed for ${domain}: ${out ? out.message : "No output"}`);
    return { error: "whois_failed" };
  }

  return { raw: out };
}

// ================= TLS =================
function tlsInfo(domain) {
  if (!checkTool("openssl")) return null;

  const out = runCmd(
    `echo | openssl s_client -connect ${domain}:443 -servername ${domain} 2>/dev/null | openssl x509 -noout -issuer -subject -dates`
  );

  if (!out || out.error) {
    return "tls_failed";
  }

  return out;
}

// ================= WHATWEB =================
function whatwebLookup(target) {
  if (!checkTool("whatweb")) return null;

  log.info(`Running technology identification on ${target}...`);
  const out = runCmd(`whatweb ${target} --color=never --no-errors`);

  if (!out || out.error) {
    return null;
  }

  return out;
}

// ================= MAIN =================
async function main() {
  try {
    const input = process.argv[2];

    if (!input) {
      throw new Error("Usage: node recon.js <target>");
    }

    let domain = extractDomain(input).trim();
    let isIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(domain);

    if (isIP) {
      log.info(`Target is an IP (${domain}), attempting reverse DNS...`);
      const resolved = await reverseDns(domain);
      if (resolved) {
        log.info(`Proceeding with resolved domain: ${resolved}`);
        domain = resolved;
        isIP = false; // It's a domain now
      } else {
        log.warn(`Could not resolve domain for ${domain}, proceeding with IP only.`);
      }
    }

    const scanId = process.env.SCAN_ID || input.replace(/[^a-z0-9.-]/gi, "_").replace(/_{2,}/g, "_").replace(/^_|_$/g, "");
    const outDir = process.env.OUTPUT_DIR || path.join("results", scanId);

    fs.mkdirSync(outDir, { recursive: true });

    log.info(`Scan ID: ${scanId}`);
    log.info(`Target: ${domain}`);
    log.info(`Output: ${outDir}`);

    updateState(outDir, "recon_init", 5, "Initializing Recon...");

    let subs = [];
    if (isIP) {
      log.info("Target is an IP, skipping subdomain discovery");
      subs = [domain];
    } else {
      updateState(outDir, "subdomain_discovery", 10, "Mapping subdomains...");
      const subfinderResults = primaryDiscovery(domain);
      const assetfinderResults = secondaryDiscovery(domain);
      subs = [...new Set([...subfinderResults, ...assetfinderResults])];

      if (!subs.length) {
        log.warn("Reverting to root domain mapping");
        subs = [domain];
      } else {
        log.info(`Consolidated unique assets: ${subs.length}`);
      }
    }

    // ===== ASSET DISCOVERY WITH HTTPX =====
    updateState(outDir, "asset_discovery", 12, "Verifying asset availability...");

    const subsFile = path.join(outDir, "subs_to_check.txt");
    fs.writeFileSync(subsFile, subs.join("\n"));

    log.info("Verifying live endpoints...");
    // -ip flag gets the IP, -silent for clean output
    const httpxOut = runCmd(`httpx-toolkit -l ${subsFile} -ip -silent`, 120000);

    const assets = {
      subdomains: [],
      ips: [],
      urls: []
    };

    if (httpxOut && !httpxOut.error) {
      const lines = httpxOut.split("\n");
      for (let line of lines) {
        if (!line.trim()) continue;

        // httpx output format: http://sub.domain.com [IP]
        const parts = line.split(" ");
        const url = parts[0];
        const ip = parts[1] ? parts[1].replace("[", "").replace("]", "") : null;
        const sub = new URL(url).hostname;

        assets.subdomains.push(sub);
        assets.urls.push(url);
        if (ip) assets.ips.push(ip);
      }
    } else {
      log.warn("Asset verification failed, falling back to basic resolution");
      // Basic fallback
      for (let sub of subs) {
        const ip = isIP ? sub : await resolveDomain(sub);
        if (ip) {
          assets.subdomains.push(sub);
          assets.ips.push(ip);
          assets.urls.push(`http://${sub}`, `https://${sub}`);
        }
      }
    }

    // Add original input if it's a URL (prepend to ensure it's scanned)
    if (input.startsWith("http")) {
      assets.urls.unshift(input);
    }

    // remove duplicates
    assets.subdomains = [...new Set(assets.subdomains)];
    assets.ips = [...new Set(assets.ips)];
    assets.urls = [...new Set(assets.urls)];

    log.info(
      `Assets → subs=${assets.subdomains.length}, ips=${assets.ips.length}, urls=${assets.urls.length}`
    );

    updateState(outDir, "recon_dns_tls", 15, `Resolved ${assets.ips.length} assets. Performing DNS/TLS checks...`);

    // ===== WHATWEB =====
    updateState(outDir, "tech_discovery", 18, "Identifying web technologies...");
    const techResults = {};
    const urlsToScan = assets.urls.slice(0, 5); // Limit to top 5 for speed
    for (const url of urlsToScan) {
      const tech = whatwebLookup(url);
      if (tech) techResults[url] = tech;
    }

    // ===== REPORT =====
    const report = {
      __meta__: {
        scan_id: scanId,
        status: "completed",
        timestamp: new Date().toISOString()
      },
      domain,
      domain_dossier: {
        dns: digRecords(domain),
        whois: await whoisLookup(domain),
        tls: tlsInfo(domain)
      },
      technologies: techResults,
      assets
    };

    const reconPath = path.join(outDir, "recon.json");
    fs.writeFileSync(reconPath, JSON.stringify(report, null, 4));

    const assetsPath = path.join(outDir, "assets.json");
    const assetsReport = { domain, assets };
    fs.writeFileSync(assetsPath, JSON.stringify(assetsReport, null, 4));

    log.info("Recon completed successfully");

  } catch (err) {
    console.error("[FATAL ERROR]", err.message);
    writeFatalError(err);
  }
}

main();
