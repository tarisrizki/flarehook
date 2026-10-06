import crypto from "node:crypto";

const targetUrl = process.argv[2] || "http://127.0.0.1:28899"; // fallback to local proxy or tunnel
const secret = "whsec_test_secret_123";
const body = JSON.stringify({
  id: "evt_test_charge_succeeded",
  type: "charge.succeeded",
  amount: 250000,
  currency: "idr",
  customer: "cus_dragontest_999"
});

const expiredTimestamp = 1700000000;
const hmac = crypto.createHmac("sha256", secret).update(`${expiredTimestamp}.${body}`).digest("hex");
const sigHeader = `t=${expiredTimestamp},v1=${hmac}`;

console.log(`📡 Sending expired Stripe webhook to: ${targetUrl}/webhook/stripe`);
console.log(`   Header: ${sigHeader}`);

try {
  const res = await fetch(`${targetUrl}/webhook/stripe`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "stripe-signature": sigHeader
    },
    body
  });

  console.log(`\n📬 Response Status: ${res.status} ${res.statusText}`);
  const text = await res.text();
  console.log(`   Body: ${text}`);
} catch (err) {
  console.error("❌ Failed to send request:", err.message);
}
