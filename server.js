import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function requireGatewayToken(req, res, next) {
  const token = req.header("x-gateway-token");
  if (!process.env.GATEWAY_TOKEN || token !== process.env.GATEWAY_TOKEN) {
    return res.status(401).json({ error: "Unauthorized gateway request" });
  }
  next();
}

function hubtelAuthHeader() {
  const raw = `${process.env.HUBTEL_CLIENT_ID}:${process.env.HUBTEL_CLIENT_SECRET}`;
  return `Basic ${Buffer.from(raw).toString("base64")}`;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "ziloshift-hubtel-gateway" }));

app.post("/api/disburse", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount, phone, currency = "GHS", worker_user_id, shift_id } = req.body || {};
    if (!reference || !amount || !phone) {
      return res.status(400).json({ error: "reference, amount, phone required" });
    }
    const body = {
      ClientReference: reference,
      Amount: Number(amount).toFixed(2),
      PrimaryCallbackUrl: process.env.HUBTEL_CALLBACK_URL,
      Description: `ZiloShift payout ${shift_id || ""}`.trim(),
      Destination: phone,
      Channel: "mtn-gh",
    };
    const response = await fetch(`${process.env.HUBTEL_DISBURSEMENT_BASE_URL}/v1/disburse`, {
      method: "POST",
      headers: {
        Authorization: hubtelAuthHeader(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({ error: "Hubtel disbursement rejected", details: data });
    }

    await supabase.from("payments").update({
      payout_provider: "hubtel_disbursement",
      payout_external_id: data?.Data?.TransactionId || data?.transactionId || null,
      status: "processing",
    }).eq("payout_reference", reference);

    await supabase.from("notifications").insert({
      user_id: worker_user_id,
      title: "Payout processing",
      subtitle: `Your Ghana payout is being processed via Hubtel (${currency}).`,
      type: "payment_update",
      icon: "wallet",
      deep_link: "/worker/earnings",
      metadata: { reference, shift_id, provider: "hubtel" },
    });

    return res.json({ ok: true, transaction_id: data?.Data?.TransactionId || data?.transactionId || null, raw: data });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/webhooks/hubtel", async (req, res) => {
  try {
    const signature = req.header("x-hubtel-signature");
    if (process.env.HUBTEL_WEBHOOK_SECRET && signature) {
      const expected = crypto.createHmac("sha256", process.env.HUBTEL_WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");
      if (expected !== signature) return res.status(401).json({ error: "Invalid signature" });
    }
    const payload = req.body || {};
    const reference = payload?.ClientReference || payload?.Data?.ClientReference || payload?.reference;
    const statusRaw = (payload?.Status || payload?.Data?.Status || "").toString().toLowerCase();
    if (!reference) return res.json({ ok: true });

    const mapped = statusRaw.includes("success") ? "paid_out" : statusRaw.includes("fail") ? "failed" : "processing";
    await supabase.from("payments").update({ status: mapped }).eq("payout_reference", reference);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

const port = Number(process.env.PORT || 8081);
app.listen(port, () => {
  console.log(`ZiloShift Hubtel gateway listening on ${port}`);
});
