#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const axios = require("axios");

// ================= CONFIG =================
const FINAL_REPORT = "final_report.json";
const STATE_FILE = "scan_state.json";

const IMPORTANT_PORTS = "21-23,25,53,80,81,88,110,111,135,139,143,443,445,548,587,631,636,873,990,993,995,1025-1029,1110,1433,1723,2000,2049,2121,3000,3128,3306,3389,3986,4848,5000,5060,5432,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9000,9100,9999";

const NUCLEI_TEMPLATES = [
  "http/cves",
  "http/vulnerabilities",
  "http/exposures",
  "http/misconfiguration",
  "http/technologies",
  "http/exposed-panels"
];

// ================= UTILS =================
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

function runCmd(cmd, timeout = 600000) { // Default 10 mins
  return new Promise((resolve) => {
    const redacted = cmd.replace(/(subfinder|assetfinder|httpx-toolkit|dig|nmap|nuclei|nikto|openssl|whois)/gi, "engine");
    console.log(`[CMD] Running specialized module: ${redacted}`);
    // Use detached: true so we can kill the process group on timeout
    const p = spawn(cmd, { shell: true, detached: true });

    let output = "";
    const timer = setTimeout(() => {
      console.log(`[TIMEOUT] Killing process after ${timeout}ms: ${cmd}`);
      try {
        if (process.platform === "win32") {
          p.kill("SIGKILL");
        } else {
          process.kill(-p.pid, "SIGKILL");
        }
      } catch (e) {
        p.kill("SIGKILL");
      }
    }, timeout);

    p.stdout.on("data", d => {
      output += d.toString();
    });

    p.stderr.on("data", d => {
      output += d.toString();
    });

    p.on("close", code => {
      clearTimeout(timer);
      resolve({ code, output });
    });
  });
}

// ================= INIT =================
function initReport(dir, domain) {
  atomicWrite(path.join(dir, FINAL_REPORT), {
    status: "running",
    domain,
    started_at: new Date().toISOString(),
    findings: []
  });
}

// ================= INFRASTRUCTURE ANALYSIS =================
async function runInfrastructureAnalysis(domain, dir) {
  updateState(dir, "infrastructure_scan", 20, "Initiating infrastructure analysis...");

  console.log(`[VULN] Analyzing service exposures on ${domain}...`);
  await runCmd(
    // Removed --min-rate 500 to prevent Railway firewalls from dropping all packets. Kept -sV -sC --script vuln for CVE detection.
    `nmap -sT -T3 -sV -sC --script vuln -p ${IMPORTANT_PORTS} ${domain} -oN "${dir}/nmap.txt"`,
    1800000 // 30 min timeout for nmap to allow full script scan
  );
  console.log(`[VULN] Service analysis completed for ${domain}`);

  updateState(dir, "infrastructure_done", 40, "Infrastructure analysis complete");
}

function parseInfrastructureResults(dir, cves) {
  const file = path.join(dir, "nmap.txt");
  if (!fs.existsSync(file)) return [];

  const content = fs.readFileSync(file, "utf-8");
  const lines = content.split("\n");
  const services = [];

  const cveMatches = content.match(/CVE-\d{4}-\d+/g);
  if (cveMatches) {
    cveMatches.forEach(c => cves.add(c));
  }

  let currentService = null;

  for (let line of lines) {
    // New service line
    if (line.match(/^\d+\/tcp/)) {
      const parts = line.trim().split(/\s+/);
      currentService = {
        port: parts[0],
        state: parts[1],
        service: parts[2],
        version: parts.slice(3).join(" "),
        scripts: []
      };
      services.push(currentService);
    } 
    // Script output line
    else if (currentService && (line.startsWith("|") || line.startsWith("|_"))) {
      currentService.scripts.push(line.trim());
    }
    // End of service section
    else if (currentService && line.trim() === "") {
      // Keep parsing for next service but clear current
      // currentService = null; // Removed to handle multiline script outputs better
    }
  }

  return services;
}

// ================= OWASP TOP 10 MAPPING =================
function mapToOwasp(name, description = "", tags = []) {
  const text = (name + " " + description + " " + (Array.isArray(tags) ? tags.join(" ") : tags)).toLowerCase();
  
  if (text.match(/sql injection|sqli|xss|cross-site scripting|command injection|crlf|ldap|ssti|injection/)) return "A03:2021-Injection";
  if (text.match(/lfi|rfi|directory traversal|path traversal|idor|bypass|unauthorized|access control|privilege escalation/)) return "A01:2021-Broken Access Control";
  if (text.match(/ssrf|server-side request forgery/)) return "A10:2021-Server-Side Request Forgery";
  if (text.match(/misconfiguration|exposed panel|debug|directory listing|cors|csrf|default|options|trace/)) return "A05:2021-Security Misconfiguration";
  if (text.match(/cve-|outdated|vulnerable component|deprecated|obsolete/)) return "A06:2021-Vulnerable and Outdated Components";
  if (text.match(/auth|credential|password|login|session|jwt|token|cookie/)) return "A07:2021-Identification and Authentication Failures";
  if (text.match(/crypto|tls|ssl|plaintext|secret|key|certificate|cipher/)) return "A02:2021-Cryptographic Failures";
  if (text.match(/deserialization|integrity|ci\/cd|pipeline/)) return "A08:2021-Software and Data Integrity Failures";
  if (text.match(/log|monitor/)) return "A09:2021-Security Logging and Monitoring Failures";
  
  return null;
}

// ================= NMAP FINDINGS =================
function extractInfrastructureFindings(services, cves) {
  const findings = [];

  for (let s of services) {
    // Basic service exposure
    if (s.state === "open") {
      if (s.service === "ssh") {
        findings.push({
          source: "Infrastructure",
          name: "SSH Service Exposed",
          severity: "medium",
          port: s.port,
          owasp: mapToOwasp("SSH Service Exposed")
        });
      }

      if (s.service.includes("http")) {
        findings.push({
          source: "Infrastructure",
          name: "Web Service Detected",
          severity: "low",
          port: s.port,
          owasp: null
        });
      }
    }

    // Process scripts
    if (s.scripts && s.scripts.length > 0) {
      let currentScript = "";
      let scriptLines = [];

      for (let sl of s.scripts) {
        if (sl.startsWith("|_") || (sl.startsWith("|") && !sl.startsWith("| "))) {
          // New script or end of script
          if (currentScript) {
            processScript(currentScript, scriptLines, findings, s.port);
          }
          currentScript = sl.replace(/^[|_ ]+/, "").split(":")[0];
          scriptLines = [sl];
        } else {
          scriptLines.push(sl);
        }
      }
      if (currentScript) {
        processScript(currentScript, scriptLines, findings, s.port);
      }
    }
  }

  if (cves) {
    cves.forEach(cve => {
      findings.push({
        source: "Infrastructure",
        name: `Vulnerability Found: ${cve}`,
        severity: "high",
        port: "N/A",
        link: `https://nvd.nist.gov/vuln/detail/${cve}`,
        owasp: mapToOwasp(`Vulnerability Found: ${cve}`)
      });
    });
  }

  return findings;
}

function processScript(name, lines, findings, port) {
  const content = lines.join("\n");

  // Filter out noise
  if (content.includes("Couldn't find") || content.includes("Problem with XML") || content.includes("ERROR:")) return;

  if (name.includes("http-wordpress-users")) {
    const users = content.match(/Username found: (\S+)/g);
    if (users) {
      findings.push({
        source: "Infrastructure",
        name: "WordPress User Enumeration",
        description: `Found ${users.length} users: ${users.map(u => u.split(": ")[1]).join(", ")}`,
        severity: "medium",
        port: port,
        owasp: mapToOwasp("WordPress User Enumeration", `Found ${users.length} users`)
      });
    }
  } else if (name.includes("http-aspnet-debug")) {
    if (content.includes("DEBUG is enabled")) {
      findings.push({
        source: "Infrastructure",
        name: "ASP.NET Debug Enabled",
        description: "Remote debugging is enabled, which may leak sensitive information.",
        severity: "high",
        port: port,
        owasp: mapToOwasp("ASP.NET Debug Enabled", "Remote debugging is enabled")
      });
    }
  } else if (name.includes("http-csrf")) {
    const forms = content.match(/Path: (\S+)/g);
    if (forms) {
      findings.push({
        source: "Infrastructure",
        name: "Possible CSRF Vulnerability",
        description: `Found ${forms.length} forms without CSRF protection. Paths: ${forms.map(f => f.split(": ")[1]).slice(0, 3).join(", ")}...`,
        severity: "medium",
        port: port,
        owasp: mapToOwasp("Possible CSRF Vulnerability")
      });
    }
  } else if (name.includes("http-enum")) {
    const entries = lines.filter(l => l.includes("/") && !l.includes("version")).length;
    if (entries > 0) {
      findings.push({
        source: "Infrastructure",
        name: "Interesting Files/Directories Found",
        description: `Nmap enumeration discovered ${entries} potentially sensitive paths (e.g., /wp-login.php, /robots.txt).`,
        severity: "medium",
        port: port,
        owasp: mapToOwasp("Interesting Files/Directories Found")
      });
    }
  } else {
    // Generic script finding for anything else that looks like a vulnerability
    if (content.toLowerCase().includes("vulnerable") || content.toLowerCase().includes("vulnerability") || content.toLowerCase().includes("exploitable")) {
      findings.push({
        source: "Infrastructure",
        name: `Dynamic Analysis Finding: ${name}`,
        description: content.substring(0, 200).replace(/[|_ ]+/g, " ").trim(),
        severity: "high",
        port: port,
        owasp: mapToOwasp(`Nmap Script Finding: ${name}`, content.substring(0, 200))
      });
    }
  }
}

// ================= SECURITY ENGINE =================
async function runEngine(urls, dir) {
  updateState(dir, "security_scan", 50, "Executing deep security engine...");

  const normalizedUrls = urls.map(u => u.startsWith("http") ? u : `https://${u}`);
  const file = path.join(dir, "urls.txt");
  fs.writeFileSync(file, normalizedUrls.join("\n"));

  const templatesDir = (process.env.HOME || "/root") + "/nuclei-templates";
  const templateArgs = NUCLEI_TEMPLATES.map(t => `-t ${templatesDir}/${t}`).join(" ");

  // Analysis engine flags:
  //   -ss host-spray = scan each host with all modules before moving to next
  //   -jle  = jsonl export
  //   -etags info = also include informational findings (technologies, etc.)
  console.log(`[VULN] Security engine processing ${normalizedUrls.length} targets...`);
  const result = await runCmd(
    // Lowered concurrency (-c 20 instead of 100) to prevent Out of Memory crashes on Railway
    `nuclei -l ${file} ${templateArgs} -c 20 -bs 10 -rl 100 -mhe 20 -ss host-spray -duc -timeout 5 -retries 0 -jle ${dir}/nuclei.jsonl 2>&1`,
    2400000
  );
  // Log the first 500 chars of output for debugging
  const preview = result.output.substring(0, 500).replace(/\n/g, " ");
  console.log(`[VULN] Analysis finished`);

  updateState(dir, "security_done", 70, "Security engine analysis complete");
}

function normalizeSeverity(sev) {
  if (sev === "info") return "low";
  if (sev === "low") return "medium";
  return sev;
}

function parseEngineResults(dir, cves) {
  const file = path.join(dir, "nuclei.jsonl");
  if (!fs.existsSync(file)) return [];

  const lines = fs.readFileSync(file, "utf-8").split("\n");
  const findings = [];

  for (let line of lines) {
    if (!line.trim()) continue;

    try {
      const j = JSON.parse(line);
      const cveMatch = j.info?.name?.match(/CVE-\d{4}-\d+/) || (j.info?.reference || []).join(" ").match(/CVE-\d{4}-\d+/);

      findings.push({
        source: "Security Engine",
        name: j.info?.name,
        severity: normalizeSeverity(j.info?.severity || "low"),
        url: j["matched-at"],
        link: cveMatch ? `https://nvd.nist.gov/vuln/detail/${cveMatch[0]}` : (j.info?.reference ? j.info.reference[0] : null),
        owasp: mapToOwasp(j.info?.name || "", j.info?.description || "", j.info?.tags || [])
      });

      (j.info?.reference || []).forEach(r => {
        const match = r.match(/CVE-\d{4}-\d+/);
        if (match) {
          cves.add(match[0]);
        }
      });

    } catch {}
  }

  return findings;
}

// ================= WEB ANALYSIS =================
async function runWebAnalysis(urls, dir) {
  updateState(dir, "web_analysis", 75, "Performing web layer analysis...");

  const findings = [];
  const CONCURRENCY = 2; // Limited concurrency for Nikto to avoid "cracking" the site
  
  for (let i = 0; i < urls.length; i += CONCURRENCY) {
    const chunk = urls.slice(i, i + CONCURRENCY);
    console.log(`[VULN] Analyzing web headers and configurations...`);
    
    await Promise.all(chunk.map(async (url) => {
      const res = await runCmd(`nikto -h ${url} -Tuning 123 -nointeractive`, 900000); // 15 min timeout, skip heavy tests
      
      const lines = res.output.split("\n");
      lines.forEach(line => {
        if (line.startsWith("+ ") && !line.match(/^\+ (Target|Server:|Multiple IPs|No CGI|Start Time:|End Time:|Scan terminated|1 host\(s\)|Your Analysis|Platform:|Scanner v)/)) {
          findings.push({
            source: "Web Analysis",
            name: line.substring(2, 50).trim() + "...",
            description: line.substring(2).trim(),
            severity: "medium",
            url: url,
            owasp: mapToOwasp(line.substring(2, 50).trim(), line.substring(2).trim())
          });
        }
      });
      console.log(`[VULN] Web analysis finished for ${url}`);
    }));
  }

  updateState(dir, "web_analysis_done", 85, "Web layer analysis complete");
  return findings;
}

// ================= CVE LOOKUP (NVD API) =================
async function getCVEInfo(cve) {
  try {
    // NVD API v2
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`;
    const res = await axios.get(url, { timeout: 10000 });
    
    if (res.data && res.data.vulnerabilities && res.data.vulnerabilities.length > 0) {
      const vuln = res.data.vulnerabilities[0].cve;
      return {
        id: vuln.id,
        description: vuln.descriptions[0].value,
        severity: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "UNKNOWN",
        score: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0,
        references: vuln.references.slice(0, 3).map(r => r.url)
      };
    }
    return null;
  } catch (err) {
    console.error(`[VULN] CVE lookup failed for ${cve}:`, err.message);
    return null;
  }
}

async function cveLookup(cves) {
  const results = {};

  for (let cve of cves) {
    const data = await getCVEInfo(cve);
    if (data) {
      results[cve] = data;
    }
  }

  return results;
}

// ================= GEO =================
async function geoLookup(ips) {
  const results = {};
  for (let ip of ips) {
    try {
      const res = await axios.get(`http://ip-api.com/json/${ip}`, { timeout: 10000 }); // 10s timeout
      results[ip] = res.data;
    } catch {
      results[ip] = { country: "unknown" };
    }
  }
  return results;
}

// ================= RISK =================
function calculateRisk(findings) {
  let score = 0;

  for (let f of findings) {
    if (f.severity === "critical") score += 30;
    else if (f.severity === "high") score += 20;
    else if (f.severity === "medium") score += 10;
    else score += 5;
  }

  return {
    score: Math.min(score, 100),
    level:
      score > 70 ? "HIGH" :
      score > 40 ? "MEDIUM" : "LOW"
  };
}

// ================= MAIN =================
async function main() {
  const file = process.argv[2];
  if (!file) return console.log("Usage: node vuln.js <assets.json>");

  const data = JSON.parse(fs.readFileSync(file));
  const dir = path.dirname(file);

  const urls = [...new Set(data.assets.urls || [])].slice(0, 3);
  const ips = [...new Set(data.assets.ips || [])];
  const domain = data.domain;

  initReport(dir, domain);
  updateState(dir, "init", 5, "Initialized");

  // SEQUENTIAL EXECUTION to prevent OOM on Railway (running Nmap, Nuclei, Nikto together crashes 500MB containers)
  const cves = new Set();

  await runInfrastructureAnalysis(domain, dir);
  await runEngine(urls, dir);
  const webFindings = await runWebAnalysis(urls, dir);

  const services = parseInfrastructureResults(dir, cves);
  const infraFindings = extractInfrastructureFindings(services, cves);
  const engineFindings = parseEngineResults(dir, cves);

  const allFindings = [
    ...infraFindings,
    ...engineFindings,
    ...webFindings
  ];

  const [cveIntel, geo] = await Promise.all([
    cveLookup(cves),
    geoLookup(ips)
  ]);

  const report = {
    status: "completed",
    domain,
    findings: allFindings,
    risk: calculateRisk(allFindings),
    attack_surface: {
      services: services, // Contains port, service, version
      urls: urls.length
    },
    geo,
    cve_intel: cveIntel
  };

  atomicWrite(path.join(dir, FINAL_REPORT), report);

  updateState(dir, "completed", 100, "Scan completed");

  console.log("✅ Scan Completed");
}

main();
