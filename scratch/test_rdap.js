const axios = require("axios");

async function rdapLookup(domain) {
  console.log(`Querying RDAP for ${domain}...`);
  try {
    const response = await axios.get(`https://rdap.org/domain/${domain}`, {
      timeout: 10000,
      headers: { 'Accept': 'application/rdap+json' }
    });
    console.log("RDAP Success:", JSON.stringify(response.data, null, 2).substring(0, 500) + "...");
  } catch (err) {
    console.log(`RDAP failed: ${err.message}`);
  }
}

rdapLookup("google.com");
