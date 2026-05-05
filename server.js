//server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import cors from "cors";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Custom request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} | Status: ${res.statusCode} | Time: ${duration}ms`);
  });
  next();
});
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function requireGatewayToken(req, res, next) {
  const token = req.header("x-gateway-token");
  const expected = process.env.HUBTEL_GATEWAY_TOKEN || process.env.GATEWAY_TOKEN;
  if (!expected || token !== expected) {
    console.log(`[AUTH FAILED] Missing or invalid x-gateway-token. Expected: ${expected ? 'set' : 'not set'}, Received: ${token ? 'set' : 'missing'}`);
    return res.status(401).json({ error: "Unauthorized gateway request" });
  }
  next();
}

function normalizeBasicAuth(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.toLowerCase().startsWith("basic ") ? raw : `Basic ${raw}`;
}

function hubtelAuthHeader(scope = "HUBTEL") {
  const basic = normalizeBasicAuth(process.env[`${scope}_BASIC_AUTH`]);
  if (basic) return basic;
  const clientId =
    process.env[`${scope}_API_ID`] ||
    process.env[`${scope}_CLIENT_ID`] ||
    process.env.HUBTEL_API_ID ||
    process.env.HUBTEL_CLIENT_ID;
  const clientSecret =
    process.env[`${scope}_API_KEY`] ||
    process.env[`${scope}_CLIENT_SECRET`] ||
    process.env.HUBTEL_API_KEY ||
    process.env.HUBTEL_CLIENT_SECRET;
  const raw = `${clientId}:${clientSecret}`;
  return `Basic ${Buffer.from(raw).toString("base64")}`;
}

function redactHubtelDetails(details) {
  if (!details || typeof details !== "object") return details;
  const json = JSON.parse(JSON.stringify(details));
  for (const key of Object.keys(json)) {
    if (/authorization|auth|token|secret|key|password/i.test(key)) {
      json[key] = "[redacted]";
    } else if (json[key] && typeof json[key] === "object") {
      json[key] = redactHubtelDetails(json[key]);
    }
  }
  return json;
}

function logHubtelFailure(scope, response, details) {
  if (response.ok) return;
  console.log(`[HUBTEL ${scope}] ${response.status} ${response.statusText || ""} ${JSON.stringify(redactHubtelDetails(details))}`);
}

function hasCredential(scope) {
  return Boolean(
    process.env[`${scope}_BASIC_AUTH`] ||
    (process.env[`${scope}_API_ID`] && process.env[`${scope}_API_KEY`]) ||
    (process.env[`${scope}_CLIENT_ID`] && process.env[`${scope}_CLIENT_SECRET`]) ||
    (process.env.HUBTEL_API_ID && process.env.HUBTEL_API_KEY) ||
    (process.env.HUBTEL_CLIENT_ID && process.env.HUBTEL_CLIENT_SECRET)
  );
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

function mapHubtelCollectionStatus(payload) {
  const rc = String(payload?.ResponseCode ?? payload?.responseCode ?? "").trim();
  const data = payload?.Data ?? payload?.data ?? {};
  const status = String(data?.Status ?? data?.status ?? payload?.Status ?? payload?.status ?? "").toLowerCase();
  if (rc === "0000" || status === "paid" || status.includes("success")) return "captured";
  if (rc === "0001" || status.includes("pending")) return "processing";
  if (rc) return "failed";
  return "processing";
}

function preapprovalBaseUrl() {
  return (process.env.HUBTEL_PREAPPROVAL_BASE_URL || "https://preapproval.hubtel.com").replace(/\/$/, "");
}

function receiveMoneyBaseUrl() {
  return (process.env.HUBTEL_RECEIVE_MONEY_BASE_URL || "https://rmp.hubtel.com").replace(/\/$/, "");
}

function requireCollectionAccount() {
  if (!process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER) {
    throw new Error("HUBTEL_MERCHANT_ACCOUNT_NUMBER missing");
  }
  return process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER;
}

function requireDisbursementAccount() {
  if (!process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER) {
    throw new Error("HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER missing (Hubtel disbursement account)");
  }
  return process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER;
}

function callbackUrl() {
  const url = process.env.HUBTEL_CALLBACK_URL;
  if (!url) throw new Error("HUBTEL_CALLBACK_URL is required");
  return url;
}

const GH_MOMO_CHANNELS = [
  { id: "mtn-gh", label: "MTN Mobile Money" },
  { id: "vodafone-gh", label: "Telecel Cash" },
  { id: "tigo-gh", label: "AirtelTigo Money" },
];

const GH_DIRECT_DEBIT_CHANNELS = [
  { id: "mtn-gh-direct-debit", label: "MTN Mobile Money" },
  { id: "vodafone-gh-direct-debit", label: "Telecel Cash" },
];

const GH_BANKS = [
  { code: "300302", name: "Standard Chartered Bank" },
  { code: "300303", name: "Absa Bank Ghana Limited" },
  { code: "300304", name: "GCB Bank Limited" },
  { code: "300305", name: "National Investment Bank" },
  { code: "300306", name: "ARB Apex Bank Limited" },
  { code: "300307", name: "Agricultural Development Bank" },
  { code: "300309", name: "Universal Merchant Bank" },
  { code: "300310", name: "Republic Bank Limited" },
  { code: "300311", name: "Zenith Bank Ghana Ltd" },
  { code: "300312", name: "Ecobank Ghana Ltd" },
  { code: "300313", name: "Cal Bank Limited" },
  { code: "300316", name: "First Atlantic Bank" },
  { code: "300317", name: "Prudential Bank Ltd" },
  { code: "300318", name: "Stanbic Bank" },
  { code: "300319", name: "First Bank of Nigeria" },
  { code: "300320", name: "Bank of Africa" },
  { code: "300322", name: "Guaranty Trust Bank" },
  { code: "300323", name: "Fidelity Bank Limited" },
  { code: "300324", name: "Sahel - Sahara Bank (BSIC)" },
  { code: "300325", name: "United Bank of Africa" },
  { code: "300329", name: "Access Bank Ltd" },
  { code: "300331", name: "Consolidated Bank Ghana" },
  { code: "300334", name: "First National Bank" },
  { code: "300362", name: "GHL Bank" },
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

app.get("/api/debug/hubtel-config", requireGatewayToken, async (_req, res) => {
  let outboundIp = null;
  let outboundIpError = null;
  try {
    const ipRes = await fetch("https://api.ipify.org?format=json");
    const ipJson = await ipRes.json();
    outboundIp = ipJson?.ip || null;
  } catch (error) {
    outboundIpError = error.message;
  }

  return res.json({
    ok: true,
    outbound_ip: outboundIp,
    outbound_ip_error: outboundIpError,
    port: Number(process.env.PORT || 8081),
    gateway_token_configured: Boolean(process.env.HUBTEL_GATEWAY_TOKEN || process.env.GATEWAY_TOKEN),
    account_numbers: {
      collection_configured: Boolean(process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER),
      disbursement_configured: Boolean(process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER),
    },
    credentials: {
      fallback_sales_configured: hasCredential("HUBTEL"),
      checkout_configured: hasCredential("HUBTEL_CHECKOUT"),
      direct_debit_configured: hasCredential("HUBTEL_DIRECT_DEBIT"),
      rnv_configured: hasCredential("HUBTEL_RNV"),
      disbursement_configured: hasCredential("HUBTEL_DISBURSEMENT"),
    },
    endpoints: {
      checkout_base_url: process.env.HUBTEL_CHECKOUT_BASE_URL || "https://payproxyapi.hubtel.com",
      preapproval_base_url: process.env.HUBTEL_PREAPPROVAL_BASE_URL || "https://preapproval.hubtel.com",
      rnv_base_url: process.env.HUBTEL_RNV_BASE_URL || "https://rnv.hubtel.com",
      receive_money_base_url: process.env.HUBTEL_RECEIVE_MONEY_BASE_URL || "https://rmp.hubtel.com",
    },
  });
});

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
    if (!banks.length) banks = GH_BANKS;
    return res.json({ ok: true, momo_channels: GH_MOMO_CHANNELS, direct_debit_channels: GH_DIRECT_DEBIT_CHANNELS, banks });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/verify-momo-account", requireGatewayToken, async (req, res) => {
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
      headers: { Authorization: hubtelAuthHeader("HUBTEL_RNV") },
    });
    const data = await response.json().catch(() => ({}));
    console.log(`[HUBTEL RNV] ${response.status} ${channel} ${normalizeGhMsisdn(phone).slice(0, 5)}***`);
    logHubtelFailure("RNV", response, data);
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

app.post("/api/verify-bank-account", requireGatewayToken, async (req, res) => {
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

app.post("/api/direct-debit/preapproval/initiate", requireGatewayToken, async (req, res) => {
  try {
    const { reference, venue_id, venue_user_id, customer_msisdn, channel, customer_name } = req.body || {};
    if (!reference || !venue_id || !venue_user_id || !customer_msisdn || !channel) {
      return res.status(400).json({ error: "reference, venue_id, venue_user_id, customer_msisdn, and channel are required" });
    }
    if (!GH_DIRECT_DEBIT_CHANNELS.some((c) => c.id === channel)) {
      return res.status(400).json({ error: "Unsupported direct debit channel" });
    }

    const collection = requireCollectionAccount();
    const clientReferenceId = hubtelDisburseClientReference(reference);
    const customerMsisdn = normalizeGhMsisdn(customer_msisdn);
    const url = `${preapprovalBaseUrl()}/api/v2/merchant/${encodeURIComponent(collection)}/preapproval/initiate`;
    const body = {
      clientReferenceId,
      customerMsisdn,
      channel,
      callbackUrl: callbackUrl(),
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_DIRECT_DEBIT"), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("DIRECT_DEBIT_PREAPPROVAL_INITIATE", response, data);
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel preapproval initiate failed", details: data });
    const rc = String(data?.responseCode ?? data?.ResponseCode ?? "");
    if (rc && rc !== "2000") return res.status(400).json({ error: "Hubtel preapproval was not accepted", responseCode: rc, details: data });

    const d = data?.data ?? data?.Data ?? {};
    await supabase.from("venues").update({
      stripe_onboarding_complete: false,
      hubtel_billing_type: "mobile_money_direct_debit",
      hubtel_direct_debit_channel: channel,
      hubtel_direct_debit_msisdn: customerMsisdn,
      hubtel_direct_debit_account_name: customer_name || null,
      hubtel_preapproval_reference: clientReferenceId,
      hubtel_preapproval_id: d.hubtelPreApprovalId || d.hubtelPreapprovalId || null,
      hubtel_preapproval_status: d.preapprovalStatus || "PENDING",
    }).eq("id", venue_id).eq("user_id", venue_user_id);

    return res.json({
      ok: true,
      reference: clientReferenceId,
      hubtel_preapproval_id: d.hubtelPreApprovalId || d.hubtelPreapprovalId || null,
      verification_type: d.verificationType || null,
      otp_prefix: d.otpPrefix || null,
      preapproval_status: d.preapprovalStatus || "PENDING",
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/direct-debit/preapproval/verify-otp", requireGatewayToken, async (req, res) => {
  try {
    const { venue_id, venue_user_id, customer_msisdn, hubtel_preapproval_id, reference, otp_code } = req.body || {};
    if (!venue_id || !venue_user_id || !customer_msisdn || !hubtel_preapproval_id || !reference || !otp_code) {
      return res.status(400).json({ error: "venue_id, venue_user_id, customer_msisdn, hubtel_preapproval_id, reference, and otp_code are required" });
    }
    const collection = requireCollectionAccount();
    const url = `${preapprovalBaseUrl()}/api/v2/merchant/${encodeURIComponent(collection)}/preapproval/verifyotp`;
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_DIRECT_DEBIT"), "Content-Type": "application/json" },
      body: JSON.stringify({
        customerMsisdn: normalizeGhMsisdn(customer_msisdn),
        hubtelPreApprovalId: hubtel_preapproval_id,
        clientReferenceId: reference,
        otpCode: otp_code,
      }),
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("DIRECT_DEBIT_VERIFY_OTP", response, data);
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel OTP verification failed", details: data });
    const rc = String(data?.responseCode ?? data?.ResponseCode ?? "");
    if (rc && rc !== "2000") return res.status(400).json({ error: "Hubtel OTP verification was not accepted", responseCode: rc, details: data });
    const d = data?.data ?? data?.Data ?? {};
    await supabase.from("venues").update({
      hubtel_preapproval_status: d.preapprovalStatus || "PENDING",
      hubtel_preapproval_id: d.hubtelPreApprovalId || d.hubtelPreapprovalId || hubtel_preapproval_id,
    }).eq("id", venue_id).eq("user_id", venue_user_id);
    return res.json({ ok: true, preapproval_status: d.preapprovalStatus || "PENDING", raw: data });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/direct-debit/preapproval/status", requireGatewayToken, async (req, res) => {
  try {
    const reference = req.query.clientReferenceId || req.query.reference;
    if (!reference) return res.status(400).json({ error: "reference is required" });
    const collection = requireCollectionAccount();
    const url = `${preapprovalBaseUrl()}/api/v2/merchant/${encodeURIComponent(collection)}/preapproval/${encodeURIComponent(String(reference))}/status`;
    const response = await fetch(url, { method: "GET", headers: { Authorization: hubtelAuthHeader("HUBTEL_DIRECT_DEBIT"), Accept: "application/json" } });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("DIRECT_DEBIT_STATUS", response, data);
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel preapproval status failed", details: data });
    return res.json({ ok: true, raw: data });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/direct-debit/charge", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount, venue_id, venue_user_id, worker_user_id, shift_id, customer_msisdn, channel, customer_name, customer_email } = req.body || {};
    if (!reference || amount == null || !venue_id || !venue_user_id || !customer_msisdn || !channel) {
      return res.status(400).json({ error: "reference, amount, venue_id, venue_user_id, customer_msisdn, and channel are required" });
    }
    if (!GH_DIRECT_DEBIT_CHANNELS.some((c) => c.id === channel)) {
      return res.status(400).json({ error: "Unsupported direct debit channel" });
    }
    const collection = requireCollectionAccount();
    const clientReference = hubtelDisburseClientReference(reference);
    const amountNum = Number(Number(amount).toFixed(2));
    const url = `${receiveMoneyBaseUrl()}/merchantaccount/merchants/${encodeURIComponent(collection)}/receive/mobilemoney`;
    const body = {
      CustomerName: customer_name || "ZiloShift venue",
      CustomerMsisdn: normalizeGhMsisdn(customer_msisdn),
      CustomerEmail: customer_email || undefined,
      Channel: channel,
      Amount: amountNum,
      PrimaryCallbackUrl: callbackUrl(),
      Description: `ZiloShift shift ${shift_id || ""}`.trim(),
      ClientReference: clientReference,
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_DIRECT_DEBIT"), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("DIRECT_DEBIT_CHARGE", response, data);
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel direct debit charge failed", details: data });
    const rc = String(data?.ResponseCode ?? data?.responseCode ?? "");
    if (rc && rc !== "0001" && rc !== "0000") {
      return res.status(400).json({ error: "Hubtel direct debit was not accepted", responseCode: rc, details: data });
    }
    const transactionId = data?.Data?.TransactionId ?? data?.data?.transactionId ?? null;
    await supabase.from("payments").update({
      status: rc === "0000" ? "captured" : "processing",
      collection_provider: "hubtel_direct_debit",
      collection_reference: clientReference,
      collection_external_id: transactionId != null ? String(transactionId) : null,
      payout_provider: "hubtel_disbursement",
    }).eq("shift_id", shift_id).eq("venue_user_id", venue_user_id);

    return res.json({
      ok: true,
      status: rc === "0000" ? "captured" : "processing",
      transaction_id: transactionId != null ? String(transactionId) : null,
      client_reference: clientReference,
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/api/checkout/initiate", requireGatewayToken, async (req, res) => {
  try {
    const {
      reference,
      amount = "1.00",
      currency = "GHS",
      description,
      return_url,
      cancellation_url,
      venue_user_id,
      venue_id,
      shift_id,
      worker_user_id,
      worker_payout,
      platform_fee,
      payment_id,
      purpose = "venue_billing_setup",
      payee_name,
      payee_mobile_number,
      payee_email,
    } = req.body || {};
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
      cancellationUrl: cancellation_url || return_url,
      clientReference,
      payeeName: payee_name || "ZiloShift",
    };
    if (payee_mobile_number) body.payeeMobileNumber = normalizeGhMsisdn(payee_mobile_number);
    if (payee_email) body.payeeEmail = payee_email;
    const r = await fetch(checkoutInitiateUrl(), {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    logHubtelFailure("CHECKOUT_INITIATE", r, data);
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
    const checkoutDirectUrl =
      data?.data?.checkoutDirectUrl ||
      data?.Data?.CheckoutDirectUrl ||
      data?.checkoutDirectUrl ||
      null;
    const checkoutId =
      data?.data?.checkoutId ||
      data?.Data?.CheckoutId ||
      data?.checkoutId ||
      null;

    const paymentPatch = {
      venue_user_id: venue_user_id || null,
      worker_user_id: worker_user_id || null,
      shift_id: shift_id || null,
      collection_provider: purpose === "venue_billing_setup" ? "hubtel_checkout_setup" : "hubtel_checkout",
      collection_reference: clientReference,
      collection_external_id: checkoutId != null ? String(checkoutId) : null,
      payout_provider: purpose === "shift_collection" ? "hubtel_disbursement" : "hubtel_checkout_setup",
      payout_reference: purpose === "venue_billing_setup" ? clientReference : null,
      amount: Number(amount),
      platform_fee: Number(platform_fee || 0),
      worker_amount: Number(worker_payout || 0),
      worker_payout: Number(worker_payout || 0),
      currency,
      status: "pending",
    };

    if (payment_id) {
      await supabase.from("payments").update(paymentPatch).eq("id", payment_id);
    } else {
      await supabase.from("payments").insert(paymentPatch);
    }

    if (purpose === "venue_billing_setup" && venue_id && venue_user_id) {
      await supabase.from("venues").update({
        stripe_onboarding_complete: false,
        hubtel_billing_type: "online_checkout",
      }).eq("id", venue_id).eq("user_id", venue_user_id);
    }

    return res.json({
      ok: true,
      checkout_url: checkoutUrl,
      checkout_direct_url: checkoutDirectUrl,
      checkout_id: checkoutId,
      reference: clientReference,
      message: purpose === "venue_billing_setup"
        ? "Open Hubtel Checkout to verify your billing profile with any supported payment option."
        : "Open Hubtel Checkout to complete payment for this shift.",
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

async function initiateHubtelDisbursement({ reference, amount, currency = "GHS", worker_user_id, shift_id, recipient, payment_id }) {
  callbackUrl();
  const disburseAccount = requireDisbursementAccount();
  const clientReference = hubtelDisburseClientReference(reference);
  const description = `ZiloShift payout ${shift_id || ""}`.trim() || "ZiloShift payout";
  const amountNum = Number(Number(amount).toFixed(2));

  let url;
  let body;

  if (recipient.type === "mobile_money") {
    if (!recipient.phone || !recipient.provider) throw new Error("mobile money recipient requires phone and provider");
    const msisdn = normalizeGhMsisdn(recipient.phone);
    if (!msisdn || msisdn.length < 12) throw new Error("Invalid Ghana mobile money number (use international format, e.g. 233XXXXXXXXX)");
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
    if (!recipient.bank_code || !recipient.account_number) throw new Error("bank recipient requires bank_code and account_number");
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
    throw new Error("Unsupported recipient type");
  }

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: hubtelAuthHeader("HUBTEL_DISBURSEMENT"),
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  logHubtelFailure(recipient.type === "bank" ? "DISBURSEMENT_BANK" : "DISBURSEMENT_MOMO", response, data);
  if (!response.ok) {
    const err = new Error("Hubtel disbursement rejected");
    err.details = data;
    err.status = response.status;
    throw err;
  }

  const rc = String(data?.ResponseCode ?? data?.responseCode ?? "");
  const okAccepted = rc === "0001" || rc === "0000";
  if (!okAccepted && rc) {
    const err = new Error("Hubtel did not accept disbursement");
    err.details = data;
    err.status = 400;
    throw err;
  }

  const transactionIdRaw =
    data?.Data?.TransactionId ?? data?.data?.transactionId ?? data?.TransactionId ?? null;
  const transactionId = transactionIdRaw != null ? String(transactionIdRaw) : null;

  const payoutPatch = {
    payout_provider: "hubtel_disbursement",
    payout_external_id: transactionId,
    payout_reference: clientReference,
    status: rc === "0000" ? "paid_out" : "processing",
  };

  if (payment_id) {
    await supabase.from("payments").update(payoutPatch).eq("id", payment_id);
  } else {
    await supabase.from("payments").update(payoutPatch).eq("payout_reference", reference);
  }

  if (worker_user_id) {
    await supabase.from("notifications").insert({
      user_id: worker_user_id,
      title: "Payout processing",
      subtitle: `Your Ghana payout is being processed via Hubtel (${currency}).`,
      type: "payment_update",
      icon: "wallet",
      deep_link: "/worker/earnings",
      metadata: { reference: clientReference, shift_id, provider: "hubtel", recipient_type: recipient.type },
    });
  }

  return { transactionId, clientReference, data };
}

app.post("/api/disburse", requireGatewayToken, async (req, res) => {
  try {
    const { reference, amount, currency = "GHS", worker_user_id, shift_id, recipient } = req.body || {};
    if (!reference || amount == null || !recipient?.type) {
      return res.status(400).json({ error: "reference, amount, recipient required" });
    }
    const result = await initiateHubtelDisbursement({ reference, amount, currency, worker_user_id, shift_id, recipient });

    return res.json({
      ok: true,
      transaction_id: result.transactionId,
      client_reference: result.clientReference,
      raw: result.data,
    });
  } catch (error) {
    return res.status(error.status || 500).json({ error: error.message, details: error.details });
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
      headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("CHECKOUT_STATUS", response, data);
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
      headers: { Authorization: hubtelAuthHeader("HUBTEL_DISBURSEMENT"), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("DISBURSEMENT_STATUS", response, data);
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
      payload.ClientReferenceId ??
      payload.clientReferenceId ??
      payload.ClientReference ??
      payload.clientReference;
    const transactionId =
      data.TransactionId ??
      data.transactionId ??
      payload.TransactionId ??
      payload.transactionId;

    const preapprovalReference = payload.ClientReferenceId ?? payload.clientReferenceId;
    const preapprovalStatus = payload.PreapprovalStatus ?? payload.preapprovalStatus;
    if (preapprovalReference && preapprovalStatus) {
      const approved = String(preapprovalStatus).toUpperCase() === "APPROVED";
      await supabase.from("venues").update({
        stripe_onboarding_complete: approved,
        hubtel_preapproval_status: String(preapprovalStatus).toUpperCase(),
        hubtel_preapproval_id: payload.HubtelPreapprovalId ?? payload.HubtelPreApprovalId ?? payload.hubtelPreapprovalId ?? null,
      }).eq("hubtel_preapproval_reference", String(preapprovalReference));
      return res.json({ ok: true });
    }

    if (!clientReference && transactionId == null) {
      return res.json({ ok: true });
    }

    let collectionPayment = null;
    if (clientReference) {
      const { data: byCollection } = await supabase
        .from("payments")
        .select("*")
        .eq("collection_reference", String(clientReference))
        .maybeSingle();
      collectionPayment = byCollection || null;
    }
    if (!collectionPayment && transactionId != null) {
      const { data: byCollectionId } = await supabase
        .from("payments")
        .select("*")
        .eq("collection_external_id", String(transactionId))
        .maybeSingle();
      collectionPayment = byCollectionId || null;
    }

    if (collectionPayment) {
      const collectionStatus = mapHubtelCollectionStatus(payload);
      await supabase.from("payments").update({
        status: collectionStatus,
        collection_external_id: transactionId != null ? String(transactionId) : collectionPayment.collection_external_id,
      }).eq("id", collectionPayment.id);

      if (collectionStatus === "captured" && collectionPayment.collection_provider === "hubtel_checkout_setup" && collectionPayment.venue_user_id) {
        await supabase.from("venues").update({
          stripe_onboarding_complete: true,
          hubtel_billing_type: "online_checkout",
        }).eq("user_id", collectionPayment.venue_user_id);
        return res.json({ ok: true });
      }

      if (collectionStatus === "captured" && collectionPayment.worker_user_id && Number(collectionPayment.worker_payout) > 0) {
        const { data: worker } = await supabase
          .from("workers")
          .select("hubtel_payout_type, hubtel_mobile_provider, hubtel_mobile_number, hubtel_mobile_account_name, hubtel_bank_code, hubtel_bank_name, hubtel_bank_account_number, hubtel_bank_account_name")
          .eq("user_id", collectionPayment.worker_user_id)
          .maybeSingle();
        const recipient = worker?.hubtel_payout_type === "bank"
          ? {
            type: "bank",
            bank_code: worker?.hubtel_bank_code || null,
            bank_name: worker?.hubtel_bank_name || null,
            account_number: worker?.hubtel_bank_account_number || null,
            account_name: worker?.hubtel_bank_account_name || null,
          }
          : {
            type: "mobile_money",
            provider: worker?.hubtel_mobile_provider || "mtn-gh",
            phone: worker?.hubtel_mobile_number || null,
            account_name: worker?.hubtel_mobile_account_name || null,
          };
        try {
          await initiateHubtelDisbursement({
            reference: `zpo_${String(collectionPayment.shift_id || collectionPayment.id).replace(/-/g, "").slice(0, 14)}_${Date.now().toString(36)}`,
            amount: collectionPayment.worker_payout,
            currency: collectionPayment.currency || "GHS",
            worker_user_id: collectionPayment.worker_user_id,
            shift_id: collectionPayment.shift_id,
            recipient,
            payment_id: collectionPayment.id,
          });
        } catch (payoutError) {
          await supabase.from("payments").update({ status: "failed" }).eq("id", collectionPayment.id);
          console.error("Hubtel payout after collection failed:", payoutError);
        }
      }

      return res.json({ ok: true });
    }

    const status = mapHubtelWebhookStatus(payload);
    if (clientReference) {
      const { data: payoutPayment } = await supabase
        .from("payments")
        .select("id,payout_provider")
        .eq("payout_reference", String(clientReference))
        .maybeSingle();
      if (payoutPayment?.payout_provider === "hubtel_preauth" || payoutPayment?.payout_provider === "hubtel_checkout_setup") {
        const setupStatus = status === "paid_out" ? "captured" : status;
        await supabase.from("payments").update({ status: setupStatus }).eq("id", payoutPayment.id);
        if (setupStatus === "captured") {
          const { data: setupPayment } = await supabase
            .from("payments")
            .select("venue_user_id")
            .eq("id", payoutPayment.id)
            .maybeSingle();
          if (setupPayment?.venue_user_id) {
            await supabase.from("venues").update({
              stripe_onboarding_complete: true,
              hubtel_billing_type: "online_checkout",
            }).eq("user_id", setupPayment.venue_user_id);
          }
        }
      } else {
        await supabase.from("payments").update({ status }).eq("payout_reference", String(clientReference));
      }
    }
    if (transactionId != null) {
      await supabase.from("payments").update({ status }).eq("payout_external_id", String(transactionId));
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
