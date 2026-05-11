#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");
const axios = require("axios");

// ================= CONFIG =================
const FINAL_REPORT = "final_report.json";
const STATE_FILE = "scan_state.json";

const IMPORTANT_PORTS = "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443";

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
    console.log(`[CMD] ${cmd}`);
    // Use detached: true so we can kill the process group on timeout
    const p = spawn(cmd, { shell: true, detached: true });

    let output = "";
    const timer = setTimeout(() => {
      console.log(`[TIMEOUT] Killing process after ${timeout}ms: ${cmd}`);
      try {
        // Kill the process group (minus sign before PID)
        process.kill(-p.pid, "SIGKILL");
      } catch (e) {
        p.kill();
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

// ================= NMAP =================
async function runNmap(domain, dir) {
  updateState(dir, "nmap", 20, "Nmap started");

  console.log(`[VULN] Nmap started on ${domain} (Aggressive mode)...`);
  await runCmd(
    `nmap -sT -T4 --min-rate 500 -sV -sC --script vuln -p ${IMPORTANT_PORTS} ${domain} -oN ${dir}/nmap.txt`,
    1200000 // 20 min timeout for nmap
  );
  console.log(`[VULN] Nmap finished for ${domain}`);

  updateState(dir, "nmap_done", 40, "Nmap completed");
}

function parseNmap(dir, cves) {
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
function extractNmapFindings(services, cves) {
  const findings = [];

  for (let s of services) {
    // Basic service exposure
    if (s.state === "open") {
      if (s.service === "ssh") {
        findings.push({
          source: "nmap",
          name: "SSH Service Exposed",
          severity: "medium",
          port: s.port,
          owasp: mapToOwasp("SSH Service Exposed")
        });
      }

      if (s.service.includes("http")) {
        findings.push({
          source: "nmap",
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
        source: "nmap",
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
        source: "nmap",
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
        source: "nmap",
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
        source: "nmap",
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
        source: "nmap",
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
        source: "nmap",
        name: `Nmap Script Finding: ${name}`,
        description: content.substring(0, 200).replace(/[|_ ]+/g, " ").trim(),
        severity: "high",
        port: port,
        owasp: mapToOwasp(`Nmap Script Finding: ${name}`, content.substring(0, 200))
      });
    }
  }
}

// ================= NUCLEI =================
async function runNuclei(urls, dir) {
  updateState(dir, "nuclei", 50, "Nuclei started");

  // Ensure all URLs have a scheme so Nuclei can scan them
  const normalizedUrls = urls.map(u => u.startsWith("http") ? u : `https://${u}`);
  const file = path.join(dir, "urls.txt");
  fs.writeFileSync(file, normalizedUrls.join("\n"));

  // Use absolute path — ~ may not expand inside spawn correctly on all systems
  const templatesDir = (process.env.HOME || "/root") + "/nuclei-templates";
  const templateArgs = NUCLEI_TEMPLATES.map(t => `-t ${templatesDir}/${t}`).join(" ");

  // Nuclei v3 flags:
  //   -nut  = no-update-templates  (NOT -no-update-templates, which is INVALID in v3)
  //   -duc  = disable-update-check (NOT -no-update-check)
  //   -ss host-spray = scan each host with all templates before moving to next
  //   -jle  = jsonl export (valid in v3)
  //   -etags info = also include informational findings (technologies, etc.)
  console.log(`[VULN] Nuclei started on ${normalizedUrls.length} targets (Concurrency: 50)...`);
  const result = await runCmd(
    `nuclei -l ${file} ${templateArgs} -c 50 -rl 150 -mhe 30 -ss host-spray -duc -timeout 5 -retries 0 -jle ${dir}/nuclei.jsonl 2>&1`,
    2400000
  );
  // Log the first 500 chars of nuclei stderr/stdout for debugging
  const preview = result.output.substring(0, 500).replace(/\n/g, " ");
  console.log(`[VULN] Nuclei output preview: ${preview}`);
  console.log(`[VULN] Nuclei finished`);

  updateState(dir, "nuclei_done", 70, "Nuclei completed");
}

function normalizeSeverity(sev) {
  if (sev === "info") return "low";
  if (sev === "low") return "medium";
  return sev;
}

function parseNuclei(dir, cves) {
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
        source: "nuclei",
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

// ================= NIKTO =================
async function runNikto(urls, dir) {
  updateState(dir, "nikto", 75, "Nikto started");

  const findings = [];
  const CONCURRENCY = 2; // Limited concurrency for Nikto to avoid "cracking" the site
  
  for (let i = 0; i < urls.length; i += CONCURRENCY) {
    const chunk = urls.slice(i, i + CONCURRENCY);
    console.log(`[VULN] Nikto batch started for ${chunk.join(", ")}...`);
    
    await Promise.all(chunk.map(async (url) => {
      const res = await runCmd(`nikto -h ${url} -Tuning 123 -nointeractive`, 900000); // 15 min timeout, skip heavy tests
      
      const lines = res.output.split("\n");
      lines.forEach(line => {
        if (line.startsWith("+ ") && !line.match(/^\+ (Target|Server:|Multiple IPs|No CGI|Start Time:|End Time:|Scan terminated|1 host\(s\)|Your Nikto|Platform:|Nikto v)/)) {
          findings.push({
            source: "nikto",
            name: line.substring(2, 50).trim() + "...",
            description: line.substring(2).trim(),
            severity: "medium",
            url: url,
            owasp: mapToOwasp(line.substring(2, 50).trim(), line.substring(2).trim())
          });
        }
      });
      console.log(`[VULN] Nikto finished for ${url}`);
    }));
  }

  updateState(dir, "nikto_done", 85, "Nikto completed");
  return findings;
}

// ================= EXPLOITDB =================
async function exploitdbLookup(cves) {
  const results = {};

  for (let cve of cves) {
    const res = await runCmd(`searchsploit --cve ${cve}`);

    const hasExploit = !res.output.includes("No Results");

    results[cve] = {
      exploitable: hasExploit,
      severity: hasExploit ? "high" : "medium",
      raw: res.output.split("\n").slice(0, 5)
    };
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

  // CONCURRENT EXECUTION to maximize speed
  const cves = new Set();

  const [_, __, niktoFindings] = await Promise.all([
    runNmap(domain, dir),
    runNuclei(urls, dir),
    runNikto(urls, dir)
  ]);

  const nmapServices = parseNmap(dir, cves);
  const nmapFindings = extractNmapFindings(nmapServices, cves);
  const nucleiFindings = parseNuclei(dir, cves);

  const [exploitdb, geo] = await Promise.all([
    exploitdbLookup(cves),
    geoLookup(ips)
  ]);

  const allFindings = [
    ...nmapFindings,
    ...nucleiFindings,
    ...niktoFindings
  ];

  const risk = calculateRisk(allFindings);

  const report = {
    status: "completed",
    domain,
    findings: allFindings,
    risk,
    attack_surface: {
      services: nmapServices, // Contains port, service, version
      urls: urls.length
    },
    geo,
    exploitdb
  };

  atomicWrite(path.join(dir, FINAL_REPORT), report);

  updateState(dir, "completed", 100, "Scan completed");

  console.log("✅ Scan Completed");
}

main();
