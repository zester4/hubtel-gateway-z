import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors());
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

const GH_MOMO_CHANNELS = [
  { id: "mtn-gh", label: "MTN Mobile Money" },
  { id: "vodafone-gh", label: "Telecel Cash" },
  { id: "tigo-gh", label: "AirtelTigo Money" },
];

async function fetchHubtelJson(url, body, method = "POST") {
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: hubtelAuthHeader(),
      "Content-Type": "application/json",
    },
    body: method === "GET" ? undefined : JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "ziloshift-hubtel-gateway" }));

app.get("/api/meta/payout-options", async (_req, res) => {
  try {
    let banks = [];
    if (process.env.HUBTEL_BANKS_URL) {
      const b = await fetchHubtelJson(process.env.HUBTEL_BANKS_URL, null, "GET");
      const source = Array.isArray(b?.data?.Data) ? b.data.Data : Array.isArray(b?.data?.data) ? b.data.data : [];
      banks = source.map((x) => ({
        code: x.BankCode || x.code || x.bankCode || x.id || "",
        name: x.BankName || x.name || x.bankName || "",
      })).filter((x) => x.code && x.name);
    }
    if (!banks.length) {
      banks = [
        { code: "GCB", name: "GCB Bank" },
        { code: "ECO", name: "Ecobank Ghana" },
        { code: "ADB", name: "Agricultural Development Bank (ADB)" },
        { code: "CAL", name: "CalBank" },
        { code: "STB", name: "Stanbic Bank Ghana" },
        { code: "ABG", name: "Absa Bank Ghana" },
        { code: "SCB", name: "Standard Chartered Bank Ghana" },
        { code: "FBL", name: "Fidelity Bank Ghana" },
        { code: "UMB", name: "Universal Merchant Bank (UMB)" },
        { code: "NIB", name: "National Investment Bank (NIB)" },
        { code: "PRU", name: "Prudential Bank" },
        { code: "CMB", name: "Consolidated Bank Ghana (CBG)" },
        { code: "RBL", name: "Republic Bank Ghana" },
        { code: "ZEB", name: "Zenith Bank Ghana" },
        { code: "GTB", name: "Guaranty Trust Bank (GTBank) Ghana" },
        { code: "ACC", name: "Access Bank Ghana" },
        { code: "SBG", name: "Societe Generale Ghana" },
        { code: "FNB", name: "First National Bank Ghana" },
        { code: "CBI", name: "Citi Bank Ghana" },
        { code: "BOA", name: "Bank of Africa Ghana" },
        { code: "UBA", name: "United Bank for Africa (UBA) Ghana" },
      ];
    }
    return res.json({ ok: true, momo_channels: GH_MOMO_CHANNELS, banks });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/verify-momo-account", async (req, res) => {
  try {
    const channel = String(req.query.channel || "").trim();
    const phone = String(req.query.phone || "").trim();
    if (!channel || !phone) {
      return res.status(400).json({ error: "channel and phone are required" });
    }
    if (!GH_MOMO_CHANNELS.some((c) => c.id === channel)) {
      return res.status(400).json({ error: "Unsupported momo channel" });
    }
    if (!process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER) {
      return res.status(500).json({ error: "HUBTEL_MERCHANT_ACCOUNT_NUMBER is missing" });
    }
    const base = process.env.HUBTEL_RNV_BASE_URL || "https://rnv.hubtel.com";
    const url = `${base}/merchantaccount/merchants/${encodeURIComponent(process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER)}/mobilemoney/verify?channel=${encodeURIComponent(channel)}&customerMsisdn=${encodeURIComponent(phone)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: hubtelAuthHeader() },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return res.status(response.status).json({ error: "Hubtel momo verification failed", details: data });
    }
    return res.json({
      ok: true,
      verified: data?.ResponseCode === "0000" && !!data?.Data?.IsRegistered,
      account_name: data?.Data?.Name || null,
      provider_status: data?.Data?.Status || null,
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/verify-bank-account", async (req, res) => {
  try {
    const { bank_code, account_number } = req.body || {};
    if (!bank_code || !account_number) {
      return res.status(400).json({ error: "bank_code and account_number are required" });
    }
    if (!process.env.HUBTEL_BANK_VERIFY_URL) {
      return res.json({
        ok: true,
        verified: false,
        message: "Bank verification URL not configured. Set HUBTEL_BANK_VERIFY_URL.",
      });
    }
    const vr = await fetchHubtelJson(process.env.HUBTEL_BANK_VERIFY_URL, { bank_code, account_number });
    if (!vr.ok) return res.status(vr.status).json({ error: "Bank verification failed", details: vr.data });
    const accountName =
      vr.data?.Data?.AccountName ||
      vr.data?.data?.account_name ||
      vr.data?.account_name ||
      vr.data?.accountName ||
      null;
    return res.json({
      ok: true,
      verified: Boolean(accountName),
      account_name: accountName,
      raw: vr.data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/disburse", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount, currency = "GHS", worker_user_id, shift_id, recipient } = req.body || {};
    if (!reference || !amount || !recipient?.type) {
      return res.status(400).json({ error: "reference, amount, recipient required" });
    }
    let body = {
      ClientReference: reference,
      Amount: Number(amount).toFixed(2),
      PrimaryCallbackUrl: process.env.HUBTEL_CALLBACK_URL,
      Description: `ZiloShift payout ${shift_id || ""}`.trim(),
    };
    if (recipient.type === "mobile_money") {
      if (!recipient.phone || !recipient.provider) {
        return res.status(400).json({ error: "mobile money recipient requires phone and provider" });
      }
      body = {
        ...body,
        Destination: recipient.phone,
        Channel: recipient.provider,
      };
    } else if (recipient.type === "bank") {
      if (!recipient.bank_code || !recipient.account_number) {
        return res.status(400).json({ error: "bank recipient requires bank_code and account_number" });
      }
      body = {
        ...body,
        Destination: recipient.account_number,
        Channel: "bank-gh",
        BankCode: recipient.bank_code,
        AccountNumber: recipient.account_number,
        AccountName: recipient.account_name || undefined,
      };
    } else {
      return res.status(400).json({ error: "Unsupported recipient type" });
    }
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
      metadata: { reference, shift_id, provider: "hubtel", recipient_type: recipient.type },
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
