const axios = require("axios");
const fs = require("fs");
const dns = require("dns").promises;

// ================= ENV =================
require("dotenv").config();

const OTX_API_KEY      = process.env.OTX_API_KEY;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY;
const VT_API_KEY       = process.env.VT_API_KEY;
const URLSCAN_API_KEY  = process.env.URLSCAN_API_KEY; // optional

const TIMEOUT = 12000;

// ================= MITRE =================
const MITRE_KEYWORDS = {
  phishing:   { technique_id: "T1566", tactic: "Initial Access" },
  downloader: { technique_id: "T1105", tactic: "Command and Control" },
  trojan:     { technique_id: "T1059", tactic: "Execution" },
  c2:         { technique_id: "T1071", tactic: "Command and Control" },
  botnet:     { technique_id: "T1496", tactic: "Impact" },
  ransomware: { technique_id: "T1486", tactic: "Impact" },
  backdoor:   { technique_id: "T1543", tactic: "Persistence" },
  exploit:    { technique_id: "T1203", tactic: "Execution" }
};

// ================= SAFE GET =================
async function safeGet(url, headers = {}, params = {}) {
  try {
    const res = await axios.get(url, { headers, params, timeout: TIMEOUT });
    return res.data;
  } catch (e) {
    return null;
  }
}

// ================= ASN RISK =================
function calculateAsnRisk(asnName) {
  if (!asnName) return 50;
  const name = asnName.toLowerCase();
  if (name.includes("amazon") || name.includes("google")) return 10;
  if (name.includes("cloudflare")) return 10;
  if (name.includes("fastly") || name.includes("akamai")) return 10;
  if (name.includes("cdn")) return 15;
  if (name.includes("zoho")) return 20;
  if (name.includes("digitalocean") || name.includes("linode") || name.includes("vultr")) return 40;
  if (name.includes("colocrossing") || name.includes("m247")) return 60;
  return 30;
}

// ================= OTX =================
async function otxLookup(endpoint) {
  if (!OTX_API_KEY) return { pulses: [], threat_pulses: [], pulse_count: 0 };

  const data = await safeGet(endpoint, { "X-OTX-API-KEY": OTX_API_KEY });
  if (!data) return { pulses: [], threat_pulses: [], pulse_count: 0 };

  const pulseCount = data.pulse_info?.count || 0;
  const pulses = (data.pulse_info?.pulses || []).slice(0, 5).map(p => ({
    name: p.name,
    type: "infrastructure",
    confidence: p.confidence || 0,
    mitre: p.attack_ids || []
  }));

  return { pulses, threat_pulses: [], pulse_count: pulseCount };
}

// ================= ABUSEIPDB =================
async function abuseipdb(ip) {
  if (!ABUSEIPDB_API_KEY) return {};

  const data = await safeGet(
    "https://api.abuseipdb.com/api/v2/check",
    { Key: ABUSEIPDB_API_KEY, Accept: "application/json" },
    { ipAddress: ip, maxAgeInDays: 90 }
  );

  if (!data) return {};
  const d = data.data || {};
  return {
    abuse_score: d.abuseConfidenceScore || 0,
    reports:     d.totalReports || 0,
    isp:         d.isp || null,
    country:     d.countryCode || null,
    usage_type:  d.usageType || null
  };
}

// ================= VIRUSTOTAL =================
async function vtLookup(endpoint) {
  if (!VT_API_KEY) return { malicious: 0, detections: [], mitre_mapping: [], metadata: {} };

  const data = await safeGet(endpoint, { "x-apikey": VT_API_KEY });
  if (!data) return { malicious: 0, detections: [], mitre_mapping: [], metadata: {} };

  const attr   = data.data?.attributes || {};
  const stats  = attr.last_analysis_stats || {};
  const results = attr.last_analysis_results || {};

  // Rich metadata even for CLEAN domains
  const metadata = {
    reputation:       attr.reputation || 0,
    categories:       Object.values(attr.categories || {}).slice(0, 3),
    registrar:        attr.registrar || null,
    creation_date:    attr.creation_date ? new Date(attr.creation_date * 1000).toISOString().split("T")[0] : null,
    last_update_date: attr.last_modification_date ? new Date(attr.last_modification_date * 1000).toISOString().split("T")[0] : null,
    country:          attr.country || null,
    tld:              attr.tld || null,
    harmless:         stats.harmless || 0,
    undetected:       stats.undetected || 0,
    suspicious:       stats.suspicious || 0
  };

  const detections = [];
  const mitreHits  = [];

  for (let [engine, res] of Object.entries(results)) {
    if (res.category === "malicious") {
      const threat = res.result || "unknown";
      detections.push({ engine, threat_name: threat });
      const t = threat.toLowerCase();
      for (let [kw, m] of Object.entries(MITRE_KEYWORDS)) {
        if (t.includes(kw)) {
          mitreHits.push({ technique_id: m.technique_id, tactic: m.tactic, matched_keyword: kw });
        }
      }
    }
  }

  return { malicious: stats.malicious || 0, detections, mitre_mapping: mitreHits, metadata };
}

// ================= SHODAN INTERNETDB (free, no key) =================
async function shodanInternetDB(ip) {
  // https://internetdb.shodan.io is completely free and requires no API key
  const data = await safeGet(`https://internetdb.shodan.io/${ip}`);
  if (!data || data.detail === "No information available") return null;

  return {
    open_ports: data.ports || [],
    hostnames:  data.hostnames || [],
    cpes:       data.cpes || [],
    vulns:      data.vulns || [],
    tags:       data.tags || []
  };
}

// ================= URLSCAN PUBLIC SEARCH (no key needed) =================
async function urlscanSearch(domain) {
  // Public search API - no API key required
  const data = await safeGet(
    `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=5`,
    { "User-Agent": "security-scanner/1.0" }
  );

  if (!data || !data.results) return { scans: [], supply_chain_risks: [] };

  const scans = data.results.slice(0, 3).map(r => ({
    url:       r.task?.url,
    country:   r.page?.country,
    server:    r.page?.server,
    ip:        r.page?.ip,
    asn:       r.page?.asn,
    asnname:   r.page?.asnname,
    malicious: r.verdicts?.overall?.malicious || false,
    score:     r.verdicts?.overall?.score || 0,
    tags:      r.verdicts?.overall?.tags || [],
    scan_date: r.task?.time
  }));

  // Build supply chain from the most recent scan's links
  const supply_chain_risks = [];
  const seen = new Set();

  for (let r of data.results.slice(0, 1)) {
    for (let [host, info] of Object.entries(r.stats?.domainStats || {})) {
      if (seen.has(host) || host.includes(domain)) continue;
      seen.add(host);
      supply_chain_risks.push({
        domain:       host,
        status:       "third-party",
        requests:     info.total || 1,
        asn_provider: r.page?.asnname || "unknown",
        asn:          r.page?.asn || null,
        country:      r.page?.country || null,
        ip:           null,
        asn_risk:     calculateAsnRisk(r.page?.asnname)
      });
    }
  }

  return { scans, supply_chain_risks };
}

// ================= URLSCAN SUBMIT (requires API key) =================
async function urlscanSubmit(url) {
  if (!URLSCAN_API_KEY) return {};

  try {
    const submit = await axios.post(
      "https://urlscan.io/api/v1/scan/",
      { url, visibility: "unlisted" },
      { headers: { "API-Key": URLSCAN_API_KEY }, timeout: TIMEOUT }
    );
    const uuid = submit.data.uuid;
    for (let i = 0; i < 5; i++) {
      await new Promise(r => setTimeout(r, 6000));
      const res = await safeGet(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (res) return res;
    }
  } catch {}
  return {};
}

// ================= SUPPLY CHAIN =================
function extractSupplyChain(data) {
  const domains = {};
  for (let req of data.data?.requests || []) {
    const response  = req.response || {};
    const respData  = response.response || {};
    const asn       = response.asn || {};
    const geo       = response.geoip || {};
    const url       = respData.url;
    if (!url) continue;
    try {
      const host = new URL(url).hostname;
      if (!domains[host]) {
        domains[host] = { requests: 0, asn_provider: asn.description, asn: asn.asn, country: geo.country, ip: respData.remoteIPAddress };
      }
      domains[host].requests++;
    } catch {}
  }
  return Object.entries(domains).map(([host, d]) => ({
    domain: host, status: "known", requests: d.requests,
    asn_provider: d.asn_provider, asn: d.asn, country: d.country, ip: d.ip,
    asn_risk: calculateAsnRisk(d.asn_provider)
  }));
}

// ================= PASSIVE DNS =================
async function passiveDNS(domain) {
  // HackerTarget passive DNS - free, no key
  const data = await safeGet(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
  if (!data || typeof data !== "string" || data.includes("error") || data.includes("API count exceeded")) return [];

  return data.split("\n")
    .filter(Boolean)
    .slice(0, 10)
    .map(line => {
      const [host, ip] = line.split(",");
      return { host: (host || "").trim(), ip: (ip || "").trim() };
    })
    .filter(r => r.host && r.ip);
}

// ================= RISK =================
function calculateRisk(vtDomain, vtUrlHits, otxData, supplyChain, ipResults) {
  let score   = 0;
  let reasons = [];

  if (vtDomain.malicious > 0) {
    score += vtDomain.malicious * 10;
    reasons.push("Domain flagged malicious by AV engines");
  }
  if (vtUrlHits > 0) {
    score += vtUrlHits * 8;
    reasons.push("URLs flagged malicious");
  }
  if ((otxData.pulses || []).length > 0) {
    score += 10;
    reasons.push("OTX threat intelligence hits");
  }
  const abusive = ipResults.filter(x => (x.abuseipdb?.abuse_score || 0) > 0);
  if (abusive.length) {
    score += 15;
    reasons.push("Abusive IP reported");
  }
  const riskyASN = supplyChain.filter(x => x.asn_risk >= 40);
  if (riskyASN.length) {
    score += 20;
    reasons.push("High-risk ASN detected");
  }
  const shodanVulns = ipResults.flatMap(x => x.shodan?.vulns || []);
  if (shodanVulns.length > 0) {
    score += shodanVulns.length * 10;
    reasons.push(`Shodan: ${shodanVulns.length} vulnerability/CVE found`);
  }

  score = Math.min(score, 100);
  let level = "LOW";
  if (score >= 80) level = "CRITICAL";
  else if (score >= 60) level = "HIGH";
  else if (score >= 30) level = "MEDIUM";

  return { score, level, reasons };
}

// ================= MAIN =================
async function runThreatIntel(domain, ips = [], urls = []) {
  console.log(`[THREAT] Starting threat intel for domain=${domain}, ips=${ips.length}, urls=${urls.length}`);

  let vtDomain      = { malicious: 0, detections: [], mitre_mapping: [], metadata: {} };
  let otxDomain     = { pulses: [], threat_pulses: [], pulse_count: 0 };
  let ipResults     = [];
  let urlResults    = [];
  let supplyChainAll = [];
  let vtUrlHits     = 0;
  let passiveDnsRecords = [];

  // --- Domain lookups ---
  if (domain) {
    console.log(`[THREAT] Querying VT + OTX for ${domain}...`);
    [vtDomain, otxDomain, passiveDnsRecords] = await Promise.all([
      vtLookup(`https://www.virustotal.com/api/v3/domains/${domain}`),
      otxLookup(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`),
      passiveDNS(domain)
    ]);
    console.log(`[THREAT] VT malicious=${vtDomain.malicious}, OTX pulses=${otxDomain.pulse_count}`);
  }

  // --- URLscan public search (no key needed) ---
  let urlscanPublic = { scans: [], supply_chain_risks: [] };
  if (domain) {
    console.log(`[THREAT] URLscan public search for ${domain}...`);
    urlscanPublic = await urlscanSearch(domain);
    supplyChainAll.push(...(urlscanPublic.supply_chain_risks || []));
    console.log(`[THREAT] URLscan: ${urlscanPublic.scans.length} scans, ${urlscanPublic.supply_chain_risks.length} supply chain entries`);
  }

  // --- IP enrichment: Shodan InternetDB + OTX + AbuseIPDB ---
  for (let ip of ips.slice(0, 5)) {
    console.log(`[THREAT] IP enrichment for ${ip}...`);
    const [otxIp, abuseData, shodanData] = await Promise.all([
      otxLookup(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`),
      abuseipdb(ip),
      shodanInternetDB(ip)
    ]);

    ipResults.push({ ip, otx: otxIp, abuseipdb: abuseData, shodan: shodanData });
    if (shodanData) {
      console.log(`[THREAT] Shodan ${ip}: ports=${shodanData.open_ports.join(",")}, vulns=${shodanData.vulns.length}`);
    }
  }

  // --- URL enrichment: VT + URLscan submit (if key exists) ---
  for (let url of urls.slice(0, 3)) {
    console.log(`[THREAT] URL enrichment for ${url}...`);
    const encoded = Buffer.from(url).toString("base64").replace(/=+$/, "");
    const [vtUrl, urlscanFull] = await Promise.all([
      vtLookup(`https://www.virustotal.com/api/v3/urls/${encoded}`),
      urlscanSubmit(url) // skipped if no API key
    ]);

    const supply = extractSupplyChain(urlscanFull);
    supplyChainAll.push(...supply);
    vtUrlHits += vtUrl.malicious || 0;

    urlResults.push({ url, virustotal: vtUrl, urlscan: urlscanFull });
  }

  // Remove duplicate supply chain entries
  const seenDomains = new Set();
  supplyChainAll = supplyChainAll.filter(s => {
    if (seenDomains.has(s.domain)) return false;
    seenDomains.add(s.domain);
    return true;
  });

  const risk = calculateRisk(vtDomain, vtUrlHits, otxDomain, supplyChainAll, ipResults);

  // Collect all MITRE hits: from VT domain + VT URLs
  const allMitre = [
    ...(vtDomain.mitre_mapping || []),
    ...urlResults.flatMap(u => u.virustotal?.mitre_mapping || [])
  ];

  // Shodan CVEs → auto-map to MITRE T1190 (Exploit Public-Facing Application)
  const shodanVulns = ipResults.flatMap(r => (r.shodan?.vulns || []).map(v => ({
    technique_id: "T1190",
    tactic: "Initial Access",
    matched_keyword: v,
    source: "shodan"
  })));
  allMitre.push(...shodanVulns);

  console.log(`[THREAT] Complete. Risk=${risk.level} (${risk.score}), MITRE=${allMitre.length}, Supply=${supplyChainAll.length}`);

  return {
    input:      urls[0] || domain,
    normalized: { ip: ips[0] || null, domain, url: urls[0] || null },

    basic_intel: {
      otx_domain:        otxDomain,
      virustotal_domain: vtDomain,
      urls_checked:      urls.length,
      ips_checked:       ips.length
    },

    passive_intel: {
      passive_dns:    passiveDnsRecords,
      urlscan_scans:  urlscanPublic.scans,
      shodan_summary: ipResults.filter(r => r.shodan).map(r => ({
        ip:         r.ip,
        open_ports: r.shodan?.open_ports || [],
        vulns:      r.shodan?.vulns || [],
        tags:       r.shodan?.tags || [],
        cpes:       r.shodan?.cpes || []
      }))
    },

    advanced_intel: {
      urls:                urlResults,
      supply_chain_risks:  supplyChainAll,
      mitre_techniques:    allMitre // consolidated from all sources
    },

    ip_intel: ipResults,

    correlation: {
      vt_detected:  vtDomain.malicious > 0 || vtUrlHits > 0,
      otx_pulses:   otxDomain.pulse_count || 0,
      shodan_vulns: ipResults.reduce((acc, r) => acc + (r.shodan?.vulns?.length || 0), 0),
      domain_age:   vtDomain.metadata?.creation_date || null
    },

    risk,
    generated_at: new Date().toISOString()
  };
}

module.exports = { runThreatIntel };
