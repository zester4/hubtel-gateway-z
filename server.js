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

/** Online Checkout: clientReference max 32 (Hubtel doc). */
function hubtelCheckoutClientReference(ref) {
  const s = String(ref ?? "").trim();
  if (!s) return crypto.randomBytes(16).toString("hex").slice(0, 32);
  if (s.length <= 32) return s;
  return crypto.createHash("sha256").update(s).digest("base64url").replace(/=/g, "").slice(0, 32);
}

/** Send money / send-to-bank: ClientReference max 36 (Hubtel doc). */
function hubtelDisburseClientReference(ref) {
  const s = String(ref ?? "").trim();
  if (!s) return `z${crypto.randomBytes(16).toString("hex").slice(0, 35)}`;
  if (s.length <= 36) return s;
  return crypto.createHash("sha256").update(s).digest("hex").slice(0, 36);
}

function normalizeGhMsisdn(phone) {
  const digits = String(phone ?? "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.startsWith("233")) return digits;
  if (digits.startsWith("0") && digits.length === 10) return `233${digits.slice(1)}`;
  return digits;
}

function checkoutInitiateUrl() {
  const base = (process.env.HUBTEL_CHECKOUT_BASE_URL || "https://payproxyapi.hubtel.com").replace(/\/$/, "");
  return `${base}/items/initiate`;
}

function mapHubtelWebhookStatus(payload) {
  const rc = String(payload?.ResponseCode ?? payload?.responseCode ?? "").trim();
  const data = payload?.Data ?? payload?.data ?? {};
  const dataStatus = String(data?.Status ?? data?.status ?? "").toLowerCase();
  const topStatus = String(payload?.Status ?? payload?.status ?? "").toLowerCase();

  if (rc === "0000") return "paid_out";
  if (rc === "0001") return "processing";
  if (rc && rc !== "0000" && rc !== "0001") return "failed";
  if (dataStatus.includes("success") || topStatus.includes("success") || dataStatus === "paid") return "paid_out";
  if (dataStatus.includes("fail") || topStatus.includes("fail")) return "failed";
  return "processing";
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

app.post("/api/preauth", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount = "1.00", currency = "GHS", description, return_url, venue_user_id, venue_id } = req.body || {};
    if (!reference) return res.status(400).json({ error: "reference is required" });
    if (!process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER) {
      return res.status(500).json({ error: "HUBTEL_MERCHANT_ACCOUNT_NUMBER missing" });
    }
    const callback = process.env.HUBTEL_PREAUTH_CALLBACK_URL || process.env.HUBTEL_CALLBACK_URL;
    if (!callback) {
      return res.status(500).json({ error: "HUBTEL_PREAUTH_CALLBACK_URL or HUBTEL_CALLBACK_URL is required for checkout" });
    }
    if (!return_url) {
      return res.status(400).json({ error: "return_url is required" });
    }
    const clientReference = hubtelCheckoutClientReference(reference);
    const body = {
      totalAmount: Number(Number(amount).toFixed(2)),
      description: description || "ZiloShift card check (auto-refund)",
      callbackUrl: callback,
      returnUrl: return_url,
      merchantAccountNumber: process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER,
      cancellationUrl: return_url,
      clientReference,
      payeeName: "ZiloShift",
    };
    const r = await fetch(checkoutInitiateUrl(), {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    const responseCode = data?.responseCode ?? data?.ResponseCode;
    if (!r.ok) return res.status(r.status).json({ error: "Hubtel checkout init failed", details: data });
    if (responseCode && responseCode !== "0000") {
      return res.status(400).json({ error: "Hubtel checkout did not return success", responseCode, details: data });
    }

    const checkoutUrl =
      data?.data?.checkoutUrl ||
      data?.Data?.CheckoutUrl ||
      data?.checkoutUrl ||
      null;

    await supabase.from("payments").insert({
      venue_user_id: venue_user_id || null,
      payout_provider: "hubtel_preauth",
      payout_reference: clientReference,
      amount: Number(amount),
      currency,
      status: "pending",
    });

    return res.json({
      ok: true,
      checkout_url: checkoutUrl,
      reference: clientReference,
      message: "₵1 will be charged then refunded automatically once authorised.",
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/disburse", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount, currency = "GHS", worker_user_id, shift_id, recipient } = req.body || {};
    if (!reference || amount == null || !recipient?.type) {
      return res.status(400).json({ error: "reference, amount, recipient required" });
    }
    if (!process.env.HUBTEL_CALLBACK_URL) {
      return res.status(500).json({ error: "HUBTEL_CALLBACK_URL is required for disbursement callbacks" });
    }
    const disburseAccount = process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER;
    if (!disburseAccount) {
      return res.status(500).json({ error: "HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER missing (Hubtel disbursement account)" });
    }

    const clientReference = hubtelDisburseClientReference(reference);
    const description = `ZiloShift payout ${shift_id || ""}`.trim() || "ZiloShift payout";
    const amountNum = Number(Number(amount).toFixed(2));

    let url;
    let body;

    if (recipient.type === "mobile_money") {
      if (!recipient.phone || !recipient.provider) {
        return res.status(400).json({ error: "mobile money recipient requires phone and provider" });
      }
      const msisdn = normalizeGhMsisdn(recipient.phone);
      if (!msisdn || msisdn.length < 12) {
        return res.status(400).json({ error: "Invalid Ghana mobile money number (use international format, e.g. 233XXXXXXXXX)" });
      }
      const recipientName = String(recipient.account_name || recipient.phone || "Recipient").trim().slice(0, 120);
      url =
        process.env.HUBTEL_SEND_MONEY_URL ||
        `https://smp.hubtel.com/api/merchants/${encodeURIComponent(disburseAccount)}/send/mobilemoney`;
      body = {
        RecipientName: recipientName,
        RecipientMsisdn: msisdn,
        Channel: recipient.provider,
        Amount: amountNum,
        PrimaryCallbackURL: process.env.HUBTEL_CALLBACK_URL,
        Description: description,
        ClientReference: clientReference,
      };
      if (recipient.customer_email) body.CustomerEmail = recipient.customer_email;
    } else if (recipient.type === "bank") {
      if (!recipient.bank_code || !recipient.account_number) {
        return res.status(400).json({ error: "bank recipient requires bank_code and account_number" });
      }
      url =
        process.env.HUBTEL_SEND_TO_BANK_URL_TEMPLATE?.replace("{BankCode}", encodeURIComponent(recipient.bank_code)) ||
        `https://smp.hubtel.com/api/merchants/${encodeURIComponent(disburseAccount)}/send/bank/gh/${encodeURIComponent(recipient.bank_code)}`;
      body = {
        Amount: amountNum,
        PrimaryCallbackUrl: process.env.HUBTEL_CALLBACK_URL,
        Description: description,
        BankAccountNumber: String(recipient.account_number),
        ClientReference: clientReference,
        BankAccountName: recipient.account_name || "",
        BankName: recipient.bank_name || "",
        BankBranch: recipient.bank_branch || "",
        BankBranchCode: recipient.bank_branch_code || "",
        RecipientPhoneNumber: recipient.phone ? normalizeGhMsisdn(recipient.phone) : "",
      };
    } else {
      return res.status(400).json({ error: "Unsupported recipient type" });
    }

    const response = await fetch(url, {
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

    const rc = String(data?.ResponseCode ?? data?.responseCode ?? "");
    const okAccepted = rc === "0001" || rc === "0000";

    if (!okAccepted && rc) {
      return res.status(400).json({ error: "Hubtel did not accept disbursement", responseCode: rc, details: data });
    }

    const transactionIdRaw =
      data?.Data?.TransactionId ?? data?.data?.transactionId ?? data?.TransactionId ?? null;
    const transactionId = transactionIdRaw != null ? String(transactionIdRaw) : null;

    const payoutPatch = {
      payout_provider: "hubtel_disbursement",
      payout_external_id: transactionId,
      status: "processing",
    };
    if (clientReference !== reference) {
      payoutPatch.payout_reference = clientReference;
    }

    await supabase.from("payments").update(payoutPatch).eq("payout_reference", reference);

    await supabase.from("notifications").insert({
      user_id: worker_user_id,
      title: "Payout processing",
      subtitle: `Your Ghana payout is being processed via Hubtel (${currency}).`,
      type: "payment_update",
      icon: "wallet",
      deep_link: "/worker/earnings",
      metadata: { reference: clientReference, shift_id, provider: "hubtel", recipient_type: recipient.type },
    });

    return res.json({
      ok: true,
      transaction_id: transactionId,
      client_reference: clientReference,
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/transaction-status/checkout", requireGatewayToken, async (req, res) => {
  try {
    const collection = process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER;
    if (!collection) return res.status(500).json({ error: "HUBTEL_MERCHANT_ACCOUNT_NUMBER missing" });
    const clientReference = req.query.clientReference || req.query.client_reference;
    const hubtelTransactionId = req.query.hubtelTransactionId || req.query.hubtel_transaction_id;
    const networkTransactionId = req.query.networkTransactionId || req.query.network_transaction_id;
    if (!clientReference && !hubtelTransactionId && !networkTransactionId) {
      return res.status(400).json({ error: "Provide clientReference (preferred), hubtelTransactionId, or networkTransactionId" });
    }
    const base = (process.env.HUBTEL_TXN_STATUS_BASE_URL || "https://api-txnstatus.hubtel.com").replace(/\/$/, "");
    const url = new URL(`${base}/transactions/${encodeURIComponent(collection)}/status`);
    if (clientReference) url.searchParams.set("clientReference", String(clientReference));
    if (hubtelTransactionId) url.searchParams.set("hubtelTransactionId", String(hubtelTransactionId));
    if (networkTransactionId) url.searchParams.set("networkTransactionId", String(networkTransactionId));

    const response = await fetch(url.toString(), {
      method: "GET",
      headers: { Authorization: hubtelAuthHeader(), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel checkout status failed", details: data });
    return res.json({ ok: true, raw: data });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/transaction-status/send-money", requireGatewayToken, async (req, res) => {
  try {
    const disburseAccount = process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER;
    if (!disburseAccount) return res.status(500).json({ error: "HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER missing" });
    const clientReference = req.query.clientReference || req.query.client_reference;
    const hubtelTransactionId = req.query.hubtelTransactionId || req.query.hubtel_transaction_id;
    const networkTransactionId = req.query.networkTransactionId || req.query.network_transaction_id;
    if (!clientReference && !hubtelTransactionId && !networkTransactionId) {
      return res.status(400).json({ error: "Provide clientReference (preferred), hubtelTransactionId, or networkTransactionId" });
    }
    const base = (process.env.HUBTEL_SEND_STATUS_BASE_URL || "https://smrsc.hubtel.com").replace(/\/$/, "");
    const url = new URL(`${base}/api/merchants/${encodeURIComponent(disburseAccount)}/transactions/status`);
    if (clientReference) url.searchParams.set("clientReference", String(clientReference));
    if (hubtelTransactionId) url.searchParams.set("hubtelTransactionId", String(hubtelTransactionId));
    if (networkTransactionId) url.searchParams.set("networkTransactionId", String(networkTransactionId));

    const response = await fetch(url.toString(), {
      method: "GET",
      headers: { Authorization: hubtelAuthHeader(), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel send-money status failed", details: data });
    return res.json({ ok: true, raw: data });
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
    const data = payload?.Data ?? payload?.data ?? {};
    const clientReference =
      data.ClientReference ??
      data.clientReference ??
      payload.ClientReference ??
      payload.clientReference;
    const transactionId =
      data.TransactionId ??
      data.transactionId ??
      payload.TransactionId ??
      payload.transactionId;

    const status = mapHubtelWebhookStatus(payload);

    if (!clientReference && transactionId == null) {
      return res.json({ ok: true });
    }

    if (transactionId != null) {
      await supabase.from("payments").update({ status }).eq("payout_external_id", String(transactionId));
    }
    if (clientReference) {
      await supabase.from("payments").update({ status }).eq("payout_reference", String(clientReference));
    }

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

const port = Number(process.env.PORT || 8081);
app.listen(port, () => {
  console.log(`ZiloShift Hubtel gateway listening on ${port}`);
});
