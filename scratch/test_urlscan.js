const axios = require("axios");
require("dotenv").config();

const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

async function testUrlscan() {
    console.log("Using API Key:", URLSCAN_API_KEY);
    
    try {
        const res = await axios.post(
            "https://urlscan.io/api/v1/scan/",
            { url: "example.com", visibility: "unlisted" },
            { 
                headers: { 
                    "API-Key": URLSCAN_API_KEY.replace(/"/g, ""), // Remove quotes if any
                    "Content-Type": "application/json"
                }, 
                timeout: 10000 
            }
        );
        console.log("Scan submitted successfully!");
        console.log("UUID:", res.data.uuid);
        console.log("Result URL:", res.data.result);
    } catch (err) {
        console.error("Scan submission failed!");
        if (err.response) {
            console.error("Status:", err.response.status);
            console.error("Data:", err.response.data);
        } else {
            console.error("Message:", err.message);
        }
    }
}

testUrlscan();
