//server.js
import express from "express";
import crypto from "crypto";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import cors from "cors";
import { verifyGhanaCard, verifyVoterId } from "./verify.js";
import { getSmsBatchStatus, getSmsStatus, sendPersonalizedSms, sendSms, smsDiagnostics } from "./sms.js";
import {
  checkBalanceTransferStatus,
  getCollectionBalance,
  getDisbursementBalance,
  initiateBalanceTransfer,
  mapBalanceTransferStatus,
  transferFailureReason,
} from "./mbtransfer.js";

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

function assertSupabaseAdminConfigured() {
  const key = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "");
  if (!process.env.SUPABASE_URL || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
  }
  if (key.startsWith("sb_publishable_") || key.startsWith("sb_anon_")) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY must be a secret/service-role key, not a publishable/anon key");
  }
  const parts = key.split(".");
  if (parts.length >= 2) {
    try {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      if (payload?.role && payload.role !== "service_role") {
        throw new Error(`SUPABASE_SERVICE_ROLE_KEY must have role service_role, not ${payload.role}`);
      }
    } catch (error) {
      if (error.message.includes("SUPABASE_SERVICE_ROLE_KEY")) throw error;
    }
  }
}

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

function hubtelVerificationAuthToken() {
  return String(process.env.HUBTEL_AUTH_TOKEN || process.env.HUBTEL_BASIC_AUTH || "").replace(/^Basic\s+/i, "");
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

function refundBaseUrl() {
  return (process.env.HUBTEL_REFUND_BASE_URL || "https://refund-api.hubtel.com").replace(/\/$/, "");
}

function refundCallbackUrl() {
  const configured = process.env.HUBTEL_REFUND_CALLBACK_URL;
  if (configured) return configured;
  const existingCallback = process.env.HUBTEL_CALLBACK_URL;
  if (!existingCallback) throw new Error("HUBTEL_REFUND_CALLBACK_URL or HUBTEL_CALLBACK_URL is required for refunds");
  return `${existingCallback.replace(/\/webhooks\/hubtel\/?$/, "").replace(/\/$/, "")}/webhooks/hubtel/refund`;
}

function supabaseFunctionUrl(name) {
  const base = process.env.SUPABASE_FUNCTIONS_BASE_URL || (process.env.SUPABASE_URL ? `${process.env.SUPABASE_URL.replace(/\/$/, "")}/functions/v1` : "");
  if (!base) throw new Error("SUPABASE_URL or SUPABASE_FUNCTIONS_BASE_URL is required");
  return `${base.replace(/\/$/, "")}/${name}`;
}

function hmacSignature(body) {
  const secret = process.env.HUBTEL_WEBHOOK_SECRET;
  if (!secret) throw new Error("HUBTEL_WEBHOOK_SECRET is required to sign Supabase callbacks");
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

async function postSignedSupabaseWebhook(name, payload) {
  const body = JSON.stringify(payload || {});
  const headers = {
    "Content-Type": "application/json",
    "x-signature": hmacSignature(body) || "",
  };
  if (process.env.SUPABASE_SERVICE_ROLE_KEY) {
    headers.Authorization = `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`;
  }
  const response = await fetch(supabaseFunctionUrl(name), {
    method: "POST",
    headers,
    body,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.log(`[SUPABASE WEBHOOK ${name}] ${response.status} ${JSON.stringify(redactHubtelDetails(data))}`);
  }
  return { ok: response.ok, status: response.status, data };
}

function mapHubtelRefundStatus(payload) {
  const rc = String(payload?.ResponseCode ?? payload?.responseCode ?? "").trim();
  const status = String(payload?.Status ?? payload?.status ?? payload?.Data?.Status ?? payload?.data?.status ?? "").toLowerCase();
  if (rc === "0000" || status.includes("success")) return "succeeded";
  if (rc === "0001" || status.includes("pending") || status.includes("processing")) return "processing";
  return "failed";
}

function mapHubtelWebhookStatus(payload) {
  const rc = String(payload?.ResponseCode ?? payload?.responseCode ?? "").trim();
  const data = payload?.Data ?? payload?.data ?? {};
  const values = [
    data?.Status,
    data?.status,
    data?.TransactionStatus,
    data?.transactionStatus,
    data?.StatusDescription,
    data?.statusDescription,
    payload?.Status,
    payload?.status,
    payload?.Message,
    payload?.message,
  ].map((value) => String(value ?? "").trim().toLowerCase()).filter(Boolean);
  const statusText = values.join(" ");

  if (rc === "0000" || values.some((value) => ["success", "successful", "paid", "paid_out", "completed", "processed"].includes(value)) || statusText.includes("success")) return "paid_out";
  if (rc === "0001" || values.some((value) => ["pending", "processing", "queued", "accepted"].includes(value)) || statusText.includes("pending") || statusText.includes("processing")) return "processing";
  if (values.some((value) => ["failed", "fail", "rejected", "declined", "cancelled", "canceled", "reversed"].includes(value)) || statusText.includes("fail") || statusText.includes("reject") || statusText.includes("declin")) return "failed";
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

function mapHubtelCheckoutTransactionStatus(payload) {
  const rc = String(payload?.ResponseCode ?? payload?.responseCode ?? "").trim().toLowerCase();
  const data = payload?.data ?? payload?.Data ?? {};
  const status = String(data?.status ?? data?.Status ?? "").trim().toLowerCase();
  const transactionStatus = String(
    data?.transactionStatus ??
    data?.TransactionStatus ??
    payload?.transactionStatus ??
    payload?.TransactionStatus ??
    ""
  ).trim().toLowerCase();
  const topStatus = String(payload?.status ?? payload?.Status ?? "").trim().toLowerCase();

  if (status === "paid" || status === "captured") return "captured";
  if (status === "unpaid") return "processing";
  if (status === "refunded") return "refunded";
  if (status === "failed" || status === "expired") return "failed";

  if (["success", "successful", "paid", "captured"].includes(transactionStatus) || transactionStatus.includes("success")) {
    return "captured";
  }
  if (["failed", "expired"].includes(transactionStatus) || transactionStatus.includes("fail")) return "failed";

  // Callback-style payloads use ResponseCode/Status=Success, while status-check
  // payloads use responseCode=0000 for both Paid and Unpaid. Only trust 0000
  // alone when there is no explicit transaction status to contradict it.
  if ((rc === "success" || rc === "0000") && ["success", "successful"].includes(topStatus)) return "captured";

  const pendingValues = ["unpaid", "pending", "processing"];
  if (
    rc === "0001" ||
    pendingValues.includes(transactionStatus) ||
    pendingValues.includes(topStatus) ||
    transactionStatus.includes("pending") ||
    transactionStatus.includes("processing") ||
    topStatus.includes("pending") ||
    topStatus.includes("processing")
  ) {
    return "processing";
  }

  if (rc && rc !== "0000" && rc !== "0001" && rc !== "success") {
    return "failed";
  }

  return "processing";
}

function preapprovalBaseUrl() {
  return (process.env.HUBTEL_PREAPPROVAL_BASE_URL || "https://preapproval.hubtel.com").replace(/\/$/, "");
}

function receiveMoneyBaseUrl() {
  return (process.env.HUBTEL_RECEIVE_MONEY_BASE_URL || "https://rmp.hubtel.com").replace(/\/$/, "");
}

function requireCollectionAccount() {
  const account = process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER || process.env.HUBTEL_ACCOUNT_NUMBER;
  if (!account) {
    throw new Error("HUBTEL_MERCHANT_ACCOUNT_NUMBER missing (or set HUBTEL_ACCOUNT_NUMBER as a fallback)");
  }
  return account;
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

function transferCallbackUrl() {
  if (process.env.HUBTEL_TRANSFER_CALLBACK_URL) return process.env.HUBTEL_TRANSFER_CALLBACK_URL;
  const base = callbackUrl();
  if (/\/webhooks\/hubtel\/?$/i.test(base)) {
    return base.replace(/\/webhooks\/hubtel\/?$/i, "/webhooks/hubtel/transfer");
  }
  return `${base.replace(/\/$/, "")}/transfer`;
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

const CHECKOUT_PAYMENT_SELECT = [
  "id",
  "venue_user_id",
  "worker_user_id",
  "shift_id",
  "collection_provider",
  "collection_reference",
  "collection_external_id",
  "collection_checkout_url",
  "collection_checkout_direct_url",
  "collection_payment_method",
  "collection_payment_channel",
  "payout_provider",
  "worker_payout",
  "amount",
  "currency",
  "created_at",
  "status",
].join(",");

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

async function updatePaymentWithOptionalFields(matcher, patch) {
  const { error } = await supabase.from("payments").update(patch).match(matcher);
  if (error?.code === "42703" || error?.code === "PGRST204") {
    const fallbackPatch = { ...patch };
    delete fallbackPatch.collection_checkout_url;
    delete fallbackPatch.collection_checkout_direct_url;
    delete fallbackPatch.collection_payment_method;
    delete fallbackPatch.collection_payment_channel;
    delete fallbackPatch.worker_amount;
    delete fallbackPatch.hubtel_transfer_reference;
    delete fallbackPatch.hubtel_transfer_external_id;
    delete fallbackPatch.hubtel_transfer_status;
    delete fallbackPatch.hubtel_transfer_amount;
    delete fallbackPatch.hubtel_transfer_checked_at;
    delete fallbackPatch.hubtel_transfer_completed_at;
    delete fallbackPatch.hubtel_transfer_failure_reason;
    const { error: fallbackError } = await supabase.from("payments").update(fallbackPatch).match(matcher);
    if (fallbackError) throw fallbackError;
  } else if (error) {
    throw error;
  }
}

async function markVenueBillingConnected(venueUserId) {
  if (!venueUserId) return;
  console.log(`[VENUE BILLING] Marking venue ${venueUserId} as connected.`);
  const { error } = await supabase.from("venues").update({
    stripe_onboarding_complete: true,
    hubtel_billing_type: "online_checkout",
  }).eq("user_id", venueUserId);
  if (error) {
    console.error(`[VENUE BILLING ERROR] Failed to update venue ${venueUserId}:`, error);
  }
}

async function markWorkerProfilePromoted(payment) {
  if (!payment?.worker_user_id) return { promoted: false };
  const externalId = `hubtel:${payment.collection_reference || payment.collection_external_id || payment.external_id || payment.id}`;
  const { data: existing } = await supabase
    .from("profile_promotions")
    .select("id")
    .eq("external_id", externalId)
    .maybeSingle();
  if (existing) return { promoted: true, duplicate: true };

  const promotedUntil = new Date();
  promotedUntil.setDate(promotedUntil.getDate() + 7);

  const { error: workerError } = await supabase
    .from("workers")
    .update({ promoted_until: promotedUntil.toISOString() })
    .eq("user_id", payment.worker_user_id);
  if (workerError) throw workerError;

  const { error: promotionError } = await supabase.from("profile_promotions").insert({
    worker_user_id: payment.worker_user_id,
    amount: Number(payment.amount || 0),
    currency: String(payment.currency || "GHS").toUpperCase(),
    provider: "hubtel",
    external_id: externalId,
    stripe_session_id: null,
  });
  if (promotionError && promotionError.code !== "23505") throw promotionError;

  return { promoted: true, duplicate: false, promoted_until: promotedUntil.toISOString() };
}

async function updateProfilePromotionWithOptionalFields(matcher, patch) {
  const { error } = await supabase.from("profile_promotions").update(patch).match(matcher);
  if (error?.code === "42703" || error?.code === "PGRST204") {
    const fallbackPatch = { ...patch };
    delete fallbackPatch.checkout_url;
    delete fallbackPatch.checkout_direct_url;
    delete fallbackPatch.checkout_id;
    delete fallbackPatch.status;
    delete fallbackPatch.promoted_until;
    const { error: fallbackError } = await supabase.from("profile_promotions").update(fallbackPatch).match(matcher);
    if (fallbackError) throw fallbackError;
  } else if (error) {
    throw error;
  }
}

async function insertProfilePromotionWithOptionalFields(patch) {
  const { error } = await supabase.from("profile_promotions").insert(patch);
  if (error?.code === "42703" || error?.code === "PGRST204") {
    const fallbackPatch = { ...patch };
    delete fallbackPatch.checkout_url;
    delete fallbackPatch.checkout_direct_url;
    delete fallbackPatch.checkout_id;
    delete fallbackPatch.status;
    delete fallbackPatch.promoted_until;
    const { error: fallbackError } = await supabase.from("profile_promotions").insert(fallbackPatch);
    if (fallbackError) throw fallbackError;
  } else if (error) {
    throw error;
  }
}

async function reconcileCheckoutPayment(payment) {
  const collection = requireCollectionAccount();
  const clientReference = payment?.collection_reference;
  const externalId = payment?.collection_external_id;
  
  if (!clientReference && !externalId) {
    return { ok: false, status: payment?.status || "pending", raw: null };
  }

  const base = (process.env.HUBTEL_TXN_STATUS_BASE_URL || "https://api-txnstatus.hubtel.com").replace(/\/$/, "");
  
  const checkStatus = async (ref, id) => {
    const url = new URL(`${base}/transactions/${encodeURIComponent(collection)}/status`);
    if (ref) url.searchParams.set("clientReference", String(ref));
    else if (id) url.searchParams.set("hubtelTransactionId", String(id));
    
    console.log(`[HUBTEL STATUS CHECK] URL: ${url.toString().replace(collection, "HIDDEN")}`);
    
    const response = await fetch(url.toString(), {
      method: "GET",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    
    // Log structure to help identify why mapping might fail
    const rc = data.ResponseCode || data.responseCode;
    const dk = data.Data ? Object.keys(data.Data).join(",") : data.data ? Object.keys(data.data).join(",") : "N/A";
    console.log(`[HUBTEL STATUS CHECK] ResponseCode: ${rc} | Keys: ${Object.keys(data).join(", ")} | DataKeys: ${dk}`);
    
    return { ok: response.ok, status: response.status, data };
  };

  let result = await checkStatus(clientReference, null);
  let status = mapHubtelCheckoutTransactionStatus(result.data);

  // If not captured and we have an externalId, try that as well
  if (status !== "captured" && externalId && externalId !== clientReference) {
    console.log(`[CHECKOUT RECONCILE] Primary fail (Status: ${status}). Trying fallback ExternalID: ${externalId}`);
    const fallbackResult = await checkStatus(null, externalId);
    const fallbackStatus = mapHubtelCheckoutTransactionStatus(fallbackResult.data);
    if (fallbackStatus === "captured") {
      result = fallbackResult;
      status = fallbackStatus;
    }
  }

  if (!result.ok && status !== "captured") {
    logHubtelFailure("CHECKOUT_STATUS_RECONCILE", { ok: result.ok, status: result.status }, result.data);
    return { ok: false, status: payment?.status || "pending", raw: result.data };
  }

  const statusData = result.data?.data ?? result.data?.Data ?? {};
  const paymentDetails = statusData?.PaymentDetails ?? statusData?.paymentDetails ?? {};
  const paymentMethod =
    statusData?.paymentMethod ??
    statusData?.PaymentMethod ??
    paymentDetails?.PaymentType ??
    paymentDetails?.paymentType ??
    null;
  const channel =
    statusData?.channel ??
    statusData?.Channel ??
    paymentDetails?.Channel ??
    paymentDetails?.channel ??
    null;
  
  console.log(`[CHECKOUT RECONCILE] Final status for ${payment.id}: ${status}`);

  await updatePaymentWithOptionalFields(
    { id: payment.id },
    {
      status,
      collection_payment_method: paymentMethod,
      collection_payment_channel: channel,
    }
  );

  if (status === "captured" && payment.collection_provider === "hubtel_checkout_setup" && payment.venue_user_id) {
    await markVenueBillingConnected(payment.venue_user_id);
  }

  return { ok: true, status, raw: result.data, payment_method: paymentMethod, payment_channel: channel };
}

async function reconcileCheckoutWithoutPayment({ venueUserId, checkoutId }) {
  if (!checkoutId) return null;

  const collection = requireCollectionAccount();
  const base = (process.env.HUBTEL_TXN_STATUS_BASE_URL || "https://api-txnstatus.hubtel.com").replace(/\/$/, "");
  const url = new URL(`${base}/transactions/${encodeURIComponent(collection)}/status`);
  url.searchParams.set("hubtelTransactionId", String(checkoutId));

  console.log(`[CHECKOUT RECOVER] No payment row found; checking Hubtel by checkout id ${checkoutId}`);
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), Accept: "application/json" },
  });
  const data = await response.json().catch(() => ({}));
  logHubtelFailure("CHECKOUT_STATUS_RECOVER", response, data);
  if (!response.ok) return null;

  const status = mapHubtelCheckoutTransactionStatus(data);
  const statusData = data?.data ?? data?.Data ?? {};
  if (status !== "captured") {
    return { ok: true, connected: false, status, raw: data };
  }

  if (venueUserId) {
    await markVenueBillingConnected(venueUserId);
  }

  const recoveredPayment = {
    venue_user_id: venueUserId || null,
    collection_provider: "hubtel_checkout_setup",
    collection_reference: statusData?.clientReference ?? statusData?.ClientReference ?? null,
    collection_external_id: String(checkoutId),
    payout_provider: "hubtel_checkout_setup",
    payout_reference: statusData?.clientReference ?? statusData?.ClientReference ?? null,
    amount: Number(statusData?.amount ?? statusData?.Amount ?? 1),
    platform_fee: 0,
    worker_amount: 0,
    worker_payout: 0,
    currency: statusData?.currencyCode ?? statusData?.CurrencyCode ?? "GHS",
    status: "captured",
  };
  const paymentDetails = statusData?.PaymentDetails ?? statusData?.paymentDetails ?? {};
  recoveredPayment.collection_payment_method = statusData?.paymentMethod ?? statusData?.PaymentMethod ?? paymentDetails?.PaymentType ?? paymentDetails?.paymentType ?? null;
  recoveredPayment.collection_payment_channel = statusData?.channel ?? statusData?.Channel ?? paymentDetails?.Channel ?? paymentDetails?.channel ?? null;

  const { error } = await supabase.from("payments").insert(recoveredPayment);
  if (error?.code === "42703") {
    const { collection_payment_method, collection_payment_channel, worker_amount, ...fallbackPayment } = recoveredPayment;
    const { error: fallbackError } = await supabase.from("payments").insert(fallbackPayment);
    if (fallbackError) console.error("[CHECKOUT RECOVER] Failed to insert recovered payment:", fallbackError);
  } else if (error) {
    console.error("[CHECKOUT RECOVER] Failed to insert recovered payment:", error);
  }

  return {
    ok: true,
    connected: true,
    status: "captured",
    reference: recoveredPayment.collection_reference,
    checkout_id: recoveredPayment.collection_external_id,
    payment_method: recoveredPayment.collection_payment_method || null,
    payment_channel: recoveredPayment.collection_payment_channel || null,
    raw: data,
  };
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "ziloshift-hubtel-gateway" }));

app.post("/api/sms/send", requireGatewayToken, async (req, res) => {
  try {
    const { to, content, from } = req.body || {};
    const result = await sendSms({ to, content, from });
    return res.status(200).json({ ok: true, result });
  } catch (error) {
    console.error("[SMS SEND ERROR]", {
      status: error.status || 500,
      message: error.message,
      details: error.details || null,
      payload: error.payload || null,
    });
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null, payload: error.payload || null });
  }
});

app.post("/api/sms/batch/personalized", requireGatewayToken, async (req, res) => {
  try {
    const { recipients, from } = req.body || {};
    const result = await sendPersonalizedSms({ recipients, from });
    return res.status(200).json({ ok: true, result });
  } catch (error) {
    console.error("[SMS BATCH ERROR]", {
      status: error.status || 500,
      message: error.message,
      details: error.details || null,
      payload: error.payload || null,
    });
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null, payload: error.payload || null });
  }
});

app.get("/api/sms/status/:messageId", requireGatewayToken, async (req, res) => {
  try {
    const result = await getSmsStatus(req.params.messageId);
    return res.status(200).json({ ok: true, result });
  } catch (error) {
    console.error("[SMS STATUS ERROR]", {
      status: error.status || 500,
      message: error.message,
      details: error.details || null,
    });
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null });
  }
});

app.get("/api/sms/batch/:batchId", requireGatewayToken, async (req, res) => {
  try {
    const result = await getSmsBatchStatus(req.params.batchId);
    return res.status(200).json({ ok: true, result });
  } catch (error) {
    console.error("[SMS BATCH STATUS ERROR]", {
      status: error.status || 500,
      message: error.message,
      details: error.details || null,
    });
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null });
  }
});

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
      collection_configured: Boolean(process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER || process.env.HUBTEL_ACCOUNT_NUMBER),
      disbursement_configured: Boolean(process.env.HUBTEL_DISBURSEMENT_ACCOUNT_NUMBER),
    },
    credentials: {
      fallback_sales_configured: hasCredential("HUBTEL"),
      checkout_configured: hasCredential("HUBTEL_CHECKOUT"),
      direct_debit_configured: hasCredential("HUBTEL_DIRECT_DEBIT"),
      rnv_configured: hasCredential("HUBTEL_RNV"),
      disbursement_configured: hasCredential("HUBTEL_DISBURSEMENT"),
      refund_configured: hasCredential("HUBTEL_REFUND"),
      sms_configured: smsDiagnostics().sms_configured,
    },
    sms: smsDiagnostics(),
    endpoints: {
      checkout_base_url: process.env.HUBTEL_CHECKOUT_BASE_URL || "https://payproxyapi.hubtel.com",
      refund_base_url: process.env.HUBTEL_REFUND_BASE_URL || "https://refund-api.hubtel.com",
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
    const collectionAccount = requireCollectionAccount();
    if (!collectionAccount) {
      return res.status(500).json({ error: "HUBTEL_MERCHANT_ACCOUNT_NUMBER is missing" });
    }
    const base = process.env.HUBTEL_RNV_BASE_URL || "https://rnv.hubtel.com";
    const url = `${base}/merchantaccount/merchants/${encodeURIComponent(collectionAccount)}/mobilemoney/verify?channel=${encodeURIComponent(channel)}&customerMsisdn=${encodeURIComponent(phone)}`;
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
    if (!GH_BANKS.some((bank) => bank.code === String(bank_code))) {
      return res.status(400).json({ error: "Unsupported Ghana bank code" });
    }
    const collection = requireCollectionAccount();
    const base = (process.env.HUBTEL_RNV_BASE_URL || "https://rnv.hubtel.com").replace(/\/$/, "");
    const url = `${base}/v2/merchantaccount/merchants/${encodeURIComponent(collection)}/bank/verify/${encodeURIComponent(bank_code)}/${encodeURIComponent(account_number)}`;
    const response = await fetch(url, {
      method: "GET",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_RNV"), Accept: "application/json" },
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("RNV_BANK", response, data);
    if (!response.ok && response.status !== 400 && response.status !== 424) {
      return res.status(response.status).json({ error: "Bank verification failed", details: data });
    }
    const accountName =
      data?.data?.name ||
      data?.Data?.Name ||
      data?.Data?.AccountName ||
      data?.account_name ||
      data?.accountName ||
      null;
    const responseCode = String(data?.responseCode ?? data?.ResponseCode ?? "");
    return res.json({
      ok: true,
      verified: responseCode === "0000" && Boolean(accountName),
      account_name: accountName,
      message: data?.message || data?.Message || null,
      response_code: responseCode,
      raw: data,
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
    assertSupabaseAdminConfigured();
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
    let merchantAccountNumber;
    try {
      merchantAccountNumber = requireCollectionAccount();
    } catch (error) {
      console.error("[CHECKOUT INITIATE CONFIG]", error.message);
      return res.status(500).json({ error: error.message });
    }
    const callback = process.env.HUBTEL_PREAUTH_CALLBACK_URL || process.env.HUBTEL_CALLBACK_URL;
    if (!callback) {
      console.error("[CHECKOUT INITIATE CONFIG] HUBTEL_PREAUTH_CALLBACK_URL or HUBTEL_CALLBACK_URL missing");
      return res.status(500).json({ error: "HUBTEL_PREAUTH_CALLBACK_URL or HUBTEL_CALLBACK_URL is required for checkout" });
    }
    if (!return_url) {
      return res.status(400).json({ error: "return_url is required" });
    }
    const isVenueBillingSetup = purpose === "venue_billing_setup";
    const isShiftCollection = purpose === "shift_collection";
    const isProfilePromotion = purpose === "profile_promotion";
    const collectionProvider = isVenueBillingSetup ? "hubtel_checkout_setup" : "hubtel_checkout";
    const payoutProvider = isShiftCollection ? "hubtel_disbursement" : isProfilePromotion ? "profile_promotion" : "hubtel_checkout_setup";
    const dedupeSince = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    let existingRows = null;
    let existingError = null;
    if (purpose === "venue_billing_setup" && venue_user_id) {
      ({ data: existingRows, error: existingError } = await supabase
        .from("payments")
        .select(CHECKOUT_PAYMENT_SELECT)
        .eq("venue_user_id", venue_user_id)
        .eq("collection_provider", collectionProvider)
        .gte("created_at", dedupeSince)
        .order("created_at", { ascending: false })
        .limit(1));
    } else if (shift_id) {
      let existingQuery = supabase
        .from("payments")
        .select(CHECKOUT_PAYMENT_SELECT)
        .eq("shift_id", shift_id)
        .eq("collection_provider", collectionProvider)
        .gte("created_at", dedupeSince)
        .order("created_at", { ascending: false })
        .limit(1);
      if (venue_user_id) existingQuery = existingQuery.eq("venue_user_id", venue_user_id);
      ({ data: existingRows, error: existingError } = await existingQuery);
    }
    if (existingError && existingError.code !== "42703") {
      console.log(`[CHECKOUT DEDUPE] ${existingError.message}`);
    }
    if (existingRows?.[0]) {
      const existing = existingRows[0];
      if ((existing.status === "pending" || existing.status === "processing") && existing.collection_reference) {
        const reconciled = await reconcileCheckoutPayment(existing);
        if (reconciled.status === "captured" && isVenueBillingSetup) {
          return res.json({
            ok: true,
            deduped: true,
            connected: true,
            status: reconciled.status,
            checkout_id: existing.collection_external_id,
            reference: existing.collection_reference,
            payment_method: reconciled.payment_method || null,
            message: "Hubtel billing profile already verified.",
          });
        }
      }
      if (existing.status === "captured" && isVenueBillingSetup) {
        await markVenueBillingConnected(venue_user_id);
        return res.json({
          ok: true,
          deduped: true,
          connected: true,
          status: existing.status,
          checkout_id: existing.collection_external_id,
          reference: existing.collection_reference,
          message: "Hubtel billing profile already verified.",
        });
      }
      if (existing.collection_checkout_url) {
        return res.json({
          ok: true,
          deduped: true,
          checkout_url: existing.collection_checkout_url,
          checkout_direct_url: existing.collection_checkout_direct_url,
          checkout_id: existing.collection_external_id,
          reference: existing.collection_reference,
          status: existing.status,
          message: isVenueBillingSetup
            ? "Existing Hubtel Checkout session returned for this venue."
            : isProfilePromotion
              ? "Existing Hubtel Checkout session returned for this profile promotion."
              : "Existing Hubtel Checkout session returned for this shift.",
        });
      }
    }
    const clientReference = hubtelCheckoutClientReference(reference);
    if (isProfilePromotion && worker_user_id) {
      const { data: existingPromo, error: promoLookupError } = await supabase
        .from("profile_promotions")
        .select("*")
        .eq("worker_user_id", worker_user_id)
        .eq("provider", "hubtel")
        .eq("external_id", `hubtel:${clientReference}`)
        .maybeSingle();
      if (promoLookupError && promoLookupError.code !== "42703" && promoLookupError.code !== "PGRST204") {
        throw promoLookupError;
      }
      if (existingPromo) {
        return res.json({
          ok: true,
          deduped: true,
          promoted: false,
          status: existingPromo.status || "pending",
          reference: clientReference,
          checkout_url: existingPromo.checkout_url || null,
          checkout_direct_url: existingPromo.checkout_direct_url || null,
          checkout_id: existingPromo.checkout_id || null,
          message: "Existing Hubtel profile promotion session returned.",
        });
      }
    }
    const body = {
      totalAmount: Number(Number(amount).toFixed(2)),
      description: description || (isProfilePromotion ? "ZiloShift profile promotion" : "ZiloShift card check (auto-refund)"),
      callbackUrl: callback,
      returnUrl: return_url,
      merchantAccountNumber,
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

    if (isProfilePromotion && worker_user_id) {
      await insertProfilePromotionWithOptionalFields({
        worker_user_id,
        amount: Number(amount),
        currency,
        provider: "hubtel",
        external_id: `hubtel:${clientReference}`,
        stripe_session_id: null,
        status: "pending",
        checkout_url: checkoutUrl,
        checkout_direct_url: checkoutDirectUrl,
        checkout_id: checkoutId != null ? String(checkoutId) : null,
      });
      return res.json({
        ok: true,
        checkout_url: checkoutUrl,
        checkout_direct_url: checkoutDirectUrl,
        checkout_id: checkoutId,
        reference: clientReference,
        message: "Open Hubtel Checkout to promote your profile for 7 days.",
        raw: data,
      });
    }

    const paymentPatch = {
      venue_user_id: venue_user_id || null,
      worker_user_id: worker_user_id || null,
      shift_id: shift_id || null,
      collection_provider: collectionProvider,
      collection_reference: clientReference,
      collection_external_id: checkoutId != null ? String(checkoutId) : null,
      collection_checkout_url: checkoutUrl,
      collection_checkout_direct_url: checkoutDirectUrl,
      payout_provider: payoutProvider,
      payout_reference: isVenueBillingSetup ? clientReference : null,
      amount: Number(amount),
      platform_fee: Number(platform_fee || 0),
      worker_amount: Number(worker_payout || 0),
      worker_payout: Number(worker_payout || 0),
      currency,
      status: "pending",
    };

    if (payment_id) {
      await updatePaymentWithOptionalFields({ id: payment_id }, paymentPatch);
    } else {
      const { error } = await supabase.from("payments").insert(paymentPatch);
      if (error?.code === "42703" || error?.code === "PGRST204") {
        const { collection_checkout_url, collection_checkout_direct_url, worker_amount, ...fallbackPatch } = paymentPatch;
        const { error: fallbackError } = await supabase.from("payments").insert(fallbackPatch);
        if (fallbackError) throw fallbackError;
      } else if (error) {
        throw error;
      }
    }

    if (isVenueBillingSetup && venue_id && venue_user_id) {
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
      message: isVenueBillingSetup
        ? "Open Hubtel Checkout to verify your billing profile with any supported payment option."
        : isProfilePromotion
          ? "Open Hubtel Checkout to promote your profile for 7 days."
          : "Open Hubtel Checkout to complete payment for this shift.",
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

function hubtelTransferReferenceForPayment(payment) {
  const base = String(payment?.shift_id || payment?.id || crypto.randomUUID()).replace(/-/g, "").slice(0, 14);
  return `ztr_${base}_${Date.now().toString(36)}`.slice(0, 36);
}

function hubtelPayoutReferenceForPayment(payment) {
  const base = String(payment?.shift_id || payment?.id || crypto.randomUUID()).replace(/-/g, "").slice(0, 14);
  return `zpo_${base}_${Date.now().toString(36)}`.slice(0, 36);
}

async function workerRecipientForPayment(payment) {
  if (!payment?.worker_user_id) throw new Error("Payment has no worker user id");
  const { data: worker, error } = await supabase
    .from("workers")
    .select("hubtel_payout_type, hubtel_mobile_provider, hubtel_mobile_number, hubtel_mobile_account_name, hubtel_bank_code, hubtel_bank_name, hubtel_bank_account_number, hubtel_bank_account_name")
    .eq("user_id", payment.worker_user_id)
    .maybeSingle();
  if (error) throw error;
  if (!worker) throw new Error("Worker payout profile not found");

  return worker?.hubtel_payout_type === "bank"
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
}

async function initiateWorkerPayoutAfterTransfer(payment) {
  if (!payment?.id || !payment?.worker_user_id || Number(payment.worker_payout || 0) <= 0) return { skipped: true };
  const existingPayoutReference = String(payment.payout_reference || "");
  if (
    payment.status === "paid_out" ||
    existingPayoutReference.startsWith("zpo_") ||
    payment.payout_external_id
  ) {
    return { skipped: true, reason: "payout_already_started" };
  }

  const recipient = await workerRecipientForPayment(payment);
  return initiateHubtelDisbursement({
    reference: hubtelPayoutReferenceForPayment(payment),
    amount: payment.worker_payout,
    currency: payment.currency || "GHS",
    worker_user_id: payment.worker_user_id,
    shift_id: payment.shift_id,
    recipient,
    payment_id: payment.id,
  });
}

async function reconcileHubtelBalanceTransfer(reference) {
  if (!reference) throw new Error("Transfer reference is required");
  const { data: payment, error } = await supabase
    .from("payments")
    .select("*")
    .eq("hubtel_transfer_reference", String(reference))
    .maybeSingle();
  if (error) throw error;
  if (!payment) return { ok: false, status: "not_found" };

  const result = await checkBalanceTransferStatus({
    collectionAccount: requireCollectionAccount(),
    reference,
  });
  if (!result.ok) {
    return { ok: false, status: payment.hubtel_transfer_status || "processing", raw: result.data };
  }

  const transferStatus = mapBalanceTransferStatus(result.data);
  const data = result.data?.Data || result.data?.data || {};
  const externalId = data.id || data.Id || payment.hubtel_transfer_external_id || null;
  const failureReason = transferStatus === "failed" ? transferFailureReason(result.data) : null;
  const patch = {
    hubtel_transfer_status: transferStatus,
    hubtel_transfer_checked_at: new Date().toISOString(),
    hubtel_transfer_external_id: externalId != null ? String(externalId) : null,
    hubtel_transfer_failure_reason: failureReason,
    status: transferStatus === "failed" ? "captured" : "processing",
  };
  if (transferStatus === "transferred") {
    patch.hubtel_transfer_completed_at = new Date().toISOString();
  }
  await updatePaymentWithOptionalFields({ id: payment.id }, patch);

  if (transferStatus !== "transferred") {
    return { ok: true, status: transferStatus, raw: result.data };
  }

  const { data: refreshedPayment } = await supabase.from("payments").select("*").eq("id", payment.id).maybeSingle();
  const payout = await initiateWorkerPayoutAfterTransfer(refreshedPayment || payment);
  return { ok: true, status: transferStatus, payout, raw: result.data };
}

function scheduleHubtelTransferStatusCheck(reference) {
  const delay = Number(process.env.HUBTEL_TRANSFER_STATUS_CHECK_DELAY_MS || 5 * 60 * 1000);
  const timer = setTimeout(() => {
    reconcileHubtelBalanceTransfer(reference).catch((error) => {
      console.error("Hubtel balance transfer delayed status check failed:", error);
    });
  }, Math.max(1000, delay));
  if (typeof timer.unref === "function") timer.unref();
}

function scheduleHubtelPayoutFunding(paymentId) {
  const delay = Number(process.env.HUBTEL_TRANSFER_INIT_DELAY_MS || 5 * 60 * 1000);
  const timer = setTimeout(async () => {
    try {
      const { data: payment, error } = await supabase.from("payments").select("*").eq("id", paymentId).maybeSingle();
      if (error) throw error;
      if (!payment) return;
      await initiateHubtelPayoutFunding(payment);
    } catch (error) {
      await updatePaymentWithOptionalFields({ id: paymentId }, {
        status: "captured",
        hubtel_transfer_status: "failed",
        hubtel_transfer_checked_at: new Date().toISOString(),
        hubtel_transfer_failure_reason: error?.details ? JSON.stringify(redactHubtelDetails(error.details)).slice(0, 1000) : error?.message || "Hubtel balance transfer failed",
      });
      console.error("Hubtel delayed payout funding failed:", error);
    }
  }, Math.max(1000, delay));
  if (typeof timer.unref === "function") timer.unref();
}

async function initiateHubtelPayoutFunding(payment) {
  if (!payment?.id || !payment?.worker_user_id || Number(payment.worker_payout || 0) <= 0) return { skipped: true };
  if (payment.hubtel_transfer_status === "transferred") {
    return initiateWorkerPayoutAfterTransfer(payment);
  }
  if (
    payment.hubtel_transfer_reference &&
    ["pending", "processing"].includes(String(payment.hubtel_transfer_status || "processing"))
  ) {
    return { skipped: true, status: payment.hubtel_transfer_status || "processing", reference: payment.hubtel_transfer_reference };
  }

  const reference = hubtelTransferReferenceForPayment(payment);
  const amount = Number(Number(payment.worker_payout).toFixed(2));
  const result = await initiateBalanceTransfer({
    collectionAccount: requireCollectionAccount(),
    disbursementAccount: requireDisbursementAccount(),
    value: amount,
    reference,
    callbackUrl: transferCallbackUrl(),
    description: `ZiloShift payout funding ${payment.shift_id || payment.id}`,
  });

  const transferStatus = mapBalanceTransferStatus(result.data);
  const data = result.data?.Data || result.data?.data || {};
  const externalId = data.id || data.Id || null;
  const failureReason = transferStatus === "failed" ? transferFailureReason(result.data) : null;
  await updatePaymentWithOptionalFields({ id: payment.id }, {
    status: transferStatus === "failed" ? "captured" : "processing",
    payout_provider: "hubtel_disbursement",
    hubtel_transfer_reference: result.clientReference,
    hubtel_transfer_external_id: externalId != null ? String(externalId) : null,
    hubtel_transfer_status: transferStatus,
    hubtel_transfer_amount: amount,
    hubtel_transfer_checked_at: new Date().toISOString(),
    hubtel_transfer_completed_at: transferStatus === "transferred" ? new Date().toISOString() : null,
    hubtel_transfer_failure_reason: failureReason,
  });

  if (!result.ok || transferStatus === "failed") {
    const err = new Error("Hubtel balance transfer was not accepted");
    err.details = result.data;
    err.status = result.status || 400;
    throw err;
  }

  if (transferStatus === "transferred") {
    const { data: refreshedPayment } = await supabase.from("payments").select("*").eq("id", payment.id).maybeSingle();
    return initiateWorkerPayoutAfterTransfer(refreshedPayment || { ...payment, hubtel_transfer_status: transferStatus });
  }

  scheduleHubtelTransferStatusCheck(result.clientReference);
  if (payment.worker_user_id) {
    await supabase.from("notifications").insert({
      user_id: payment.worker_user_id,
      title: "Payout funding started",
      subtitle: "Your payout is being funded from the venue payment before it is sent to you.",
      type: "payment_update",
      icon: "wallet",
      deep_link: "/worker/earnings",
      metadata: { reference: result.clientReference, shift_id: payment.shift_id, provider: "hubtel_balance_transfer" },
    });
  }

  return { transfer_reference: result.clientReference, status: transferStatus, raw: result.data };
}

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

app.get("/api/balance-transfer/balances", requireGatewayToken, async (_req, res) => {
  try {
    const [collection, disbursement] = await Promise.all([
      getCollectionBalance({ collectionAccount: requireCollectionAccount() }),
      getDisbursementBalance({ disbursementAccount: requireDisbursementAccount() }),
    ]);
    return res.json({
      ok: collection.ok && disbursement.ok,
      collection: collection.data,
      disbursement: disbursement.data,
    });
  } catch (error) {
    return res.status(error.status || 500).json({ error: error.message, details: error.details });
  }
});

app.get("/api/balance-transfer/status", requireGatewayToken, async (req, res) => {
  try {
    let reference = String(req.query.clientReference || req.query.reference || "").trim();
    const paymentId = String(req.query.payment_id || "").trim();
    if (!reference && paymentId) {
      const { data: payment, error } = await supabase
        .from("payments")
        .select("hubtel_transfer_reference")
        .eq("id", paymentId)
        .maybeSingle();
      if (error) throw error;
      reference = String(payment?.hubtel_transfer_reference || "");
    }
    if (!reference) return res.status(400).json({ error: "clientReference/reference or payment_id is required" });
    const result = await reconcileHubtelBalanceTransfer(reference);
    return res.json(result);
  } catch (error) {
    return res.status(error.status || 500).json({ error: error.message, details: error.details });
  }
});

app.get("/api/transaction-status/checkout", requireGatewayToken, async (req, res) => {
  try {
    const collection = requireCollectionAccount();
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

app.get("/api/checkout/setup-status", requireGatewayToken, async (req, res) => {
  try {
    assertSupabaseAdminConfigured();
    const venueUserId = String(req.query.venue_user_id || req.query.venueUserId || "").trim();
    const reference = String(req.query.reference || "").trim();
    const checkoutId = String(req.query.checkout_id || req.query.checkoutid || "").trim();
    if (!venueUserId && !reference && !checkoutId) {
      return res.status(400).json({ error: "venue_user_id, reference, or checkout_id is required" });
    }

    let query = supabase
      .from("payments")
      .select(CHECKOUT_PAYMENT_SELECT)
      .eq("collection_provider", "hubtel_checkout_setup")
      .order("created_at", { ascending: false })
      .limit(1);
    if (reference) {
      query = query.eq("collection_reference", reference);
      if (venueUserId) query = query.eq("venue_user_id", venueUserId);
    } else if (checkoutId) {
      query = query.eq("collection_external_id", checkoutId);
      if (venueUserId) query = query.eq("venue_user_id", venueUserId);
    } else {
      query = query.eq("venue_user_id", venueUserId);
    }

    let { data: rows, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Hubtel returns only checkoutid on the browser return URL. If an older row
    // missed collection_external_id for any reason, fall back to the venue's most
    // recent setup checkout and reconcile by clientReference.
    if (!rows?.[0] && checkoutId && venueUserId) {
      const fallback = await supabase
        .from("payments")
        .select(CHECKOUT_PAYMENT_SELECT)
        .eq("collection_provider", "hubtel_checkout_setup")
        .eq("venue_user_id", venueUserId)
        .order("created_at", { ascending: false })
        .limit(1);
      if (fallback.error) return res.status(500).json({ error: fallback.error.message });
      rows = fallback.data || [];
    }

    const payment = rows?.[0];
    if (!payment) {
      const recovered = await reconcileCheckoutWithoutPayment({ venueUserId, checkoutId });
      if (recovered) return res.json(recovered);
      return res.json({ ok: true, connected: false, status: "not_found" });
    }
    if (payment.status === "captured") {
      await markVenueBillingConnected(payment.venue_user_id);
      return res.json({
        ok: true,
        connected: true,
        status: "captured",
        checkout_id: payment.collection_external_id,
        reference: payment.collection_reference,
        checkout_url: payment.collection_checkout_url || null,
        checkout_direct_url: payment.collection_checkout_direct_url || null,
      });
    }

    const reconciled = await reconcileCheckoutPayment(payment);
    return res.json({
      ok: reconciled.ok,
      connected: reconciled.status === "captured",
      status: reconciled.status,
      checkout_id: payment.collection_external_id,
      reference: payment.collection_reference,
      checkout_url: payment.collection_checkout_url || null,
      checkout_direct_url: payment.collection_checkout_direct_url || null,
      payment_method: reconciled.payment_method || null,
      payment_channel: reconciled.payment_channel || null,
      raw: reconciled.raw,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.get("/api/profile-promotion/status", requireGatewayToken, async (req, res) => {
  try {
    assertSupabaseAdminConfigured();
    const workerUserId = String(req.query.worker_user_id || req.query.workerUserId || "").trim();
    const reference = String(req.query.reference || "").trim();
    const checkoutId = String(req.query.checkout_id || req.query.checkoutid || "").trim();
    if (!workerUserId && !reference && !checkoutId) {
      return res.status(400).json({ error: "worker_user_id, reference, or checkout_id is required" });
    }

    let query = supabase
      .from("profile_promotions")
      .select("*")
      .eq("provider", "hubtel")
      .order("created_at", { ascending: false })
      .limit(1);
    if (reference) {
      query = query.eq("external_id", String(reference).startsWith("hubtel:") ? reference : `hubtel:${reference}`);
      if (workerUserId) query = query.eq("worker_user_id", workerUserId);
    } else if (checkoutId) {
      query = query.eq("checkout_id", checkoutId);
      if (workerUserId) query = query.eq("worker_user_id", workerUserId);
    } else {
      query = query.eq("worker_user_id", workerUserId);
    }

    let { data: rows, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    if (!rows?.[0] && checkoutId && workerUserId) {
      const fallback = await supabase
        .from("profile_promotions")
        .select("*")
        .eq("provider", "hubtel")
        .eq("worker_user_id", workerUserId)
        .order("created_at", { ascending: false })
        .limit(1);
      if (fallback.error) return res.status(500).json({ error: fallback.error.message });
      rows = fallback.data || [];
    }

    const promotionRow = rows?.[0];
    if (!promotionRow) return res.json({ ok: true, promoted: false, status: "not_found" });
    const clientReference = String(promotionRow.external_id || "").replace(/^hubtel:/, "");
    const paymentLike = {
      ...promotionRow,
      worker_user_id: promotionRow.worker_user_id,
      collection_reference: clientReference,
      collection_external_id: promotionRow.checkout_id || checkoutId || null,
      collection_checkout_url: promotionRow.checkout_url || null,
      collection_checkout_direct_url: promotionRow.checkout_direct_url || null,
      status: promotionRow.status || "pending",
    };

    if (promotionRow.status === "captured") {
      const promotion = await markWorkerProfilePromoted(paymentLike);
      return res.json({
        ok: true,
        promoted: true,
        status: "captured",
        checkout_id: promotionRow.checkout_id || null,
        reference: clientReference,
        promoted_until: promotion.promoted_until || null,
      });
    }

    const reconciled = await reconcileCheckoutPayment(paymentLike);
    if (reconciled.status === "captured") {
      const promotedUntil = new Date();
      promotedUntil.setDate(promotedUntil.getDate() + 7);
      await supabase.from("workers").update({ promoted_until: promotedUntil.toISOString() }).eq("user_id", promotionRow.worker_user_id);
      await updateProfilePromotionWithOptionalFields({ id: promotionRow.id }, {
        status: "captured",
        promoted_until: promotedUntil.toISOString(),
        checkout_id: paymentLike.collection_external_id,
      });
      return res.json({
        ok: true,
        promoted: true,
        status: "captured",
        checkout_id: paymentLike.collection_external_id,
        reference: clientReference,
        promoted_until: promotedUntil.toISOString(),
        payment_method: reconciled.payment_method || null,
        payment_channel: reconciled.payment_channel || null,
        raw: reconciled.raw,
      });
    }
    return res.json({
      ok: reconciled.ok,
      promoted: false,
      status: reconciled.status,
      checkout_id: paymentLike.collection_external_id,
      reference: clientReference,
      checkout_url: paymentLike.collection_checkout_url || null,
      checkout_direct_url: paymentLike.collection_checkout_direct_url || null,
      payment_method: reconciled.payment_method || null,
      payment_channel: reconciled.payment_channel || null,
      raw: reconciled.raw,
    });
  } catch (error) {
    console.error("[CHECKOUT INITIATE ERROR]", error);
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

app.post("/api/verify/ghana-card", requireGatewayToken, async (req, res) => {
  try {
    const result = await verifyGhanaCard(req.body?.scan_data || req.body?.card_data, {
      collectionAccountNumber: process.env.HUBTEL_ACCOUNT_NUMBER || process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER,
      basicAuthToken: hubtelVerificationAuthToken() || hubtelAuthHeader("HUBTEL_RNV"),
    });
    return res.json(result);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/verify/voter-id", requireGatewayToken, async (req, res) => {
  try {
    const result = await verifyVoterId(req.body?.voter_data || req.body, {
      collectionAccountNumber: process.env.HUBTEL_ACCOUNT_NUMBER || process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER,
      basicAuthToken: hubtelVerificationAuthToken() || hubtelAuthHeader("HUBTEL_RNV"),
    });
    return res.json(result);
  } catch (error) {
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/checkout/refund", requireGatewayToken, async (req, res) => {
  try {
    const {
      checkout_id,
      reference,
      amount,
      currency = "GHS",
      reason = "requested_by_customer",
      refund_id,
      payment_method,
    } = req.body || {};
    if (!checkout_id && !reference) {
      return res.status(400).json({ error: "checkout_id or reference is required" });
    }
    if (amount == null) {
      return res.status(400).json({ error: "amount is required" });
    }
    const collection = requireCollectionAccount();

    let payment = null;
    if (reference) {
      const { data } = await supabase
        .from("payments")
        .select("*")
        .eq("collection_reference", String(reference))
        .maybeSingle();
      payment = data || null;
    }
    if (!payment && checkout_id) {
      const { data } = await supabase
        .from("payments")
        .select("*")
        .eq("collection_external_id", String(checkout_id))
        .maybeSingle();
      payment = data || null;
    }

    const orderId = String(checkout_id || payment?.collection_external_id || "").trim();
    if (!orderId) {
      return res.status(400).json({ error: "Hubtel order/checkout id is required to refund this payment" });
    }

    const callback = refundCallbackUrl();
    const method = String(payment_method || payment?.collection_method || payment?.payment_method || "").toLowerCase();
    const usePosReversal = method === "cash" || method === "cheque" || method === "check";
    const posReversalUrl = process.env.HUBTEL_POS_REVERSAL_URL;
    if (usePosReversal && !posReversalUrl) {
      return res.status(501).json({ error: "HUBTEL_POS_REVERSAL_URL is required for cash/cheque reversal" });
    }
    const url = usePosReversal
      ? posReversalUrl
      : `${refundBaseUrl()}/refund/${encodeURIComponent(collection)}/order/${encodeURIComponent(orderId)}`;
    const body = usePosReversal
      ? {
        checkoutId: orderId,
        clientReference: reference || payment?.collection_reference || null,
        amount: Number(amount),
        currency,
        reason,
        callbackUrl: callback,
      }
      : { callbackUrl: callback };
    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: hubtelAuthHeader("HUBTEL_REFUND"),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    logHubtelFailure("REFUND", response, data);
    const status = mapHubtelRefundStatus(data);
    const payload = {
      refund_id: refund_id || null,
      payment_id: payment?.id || null,
      shift_id: payment?.shift_id || null,
      checkout_id: orderId,
      reference: reference || payment?.collection_reference || null,
      amount: Number(amount),
      currency,
      reason,
      provider: "hubtel",
      status,
      raw: data,
    };

    if (!response.ok || status === "failed" || status === "succeeded") {
      await postSignedSupabaseWebhook("hubtel-refund-webhook", payload).catch((error) => {
        console.log(`[SUPABASE WEBHOOK hubtel-refund-webhook] ${error.message}`);
      });
    }
    if (!response.ok || status === "failed") {
      return res.status(response.ok ? 400 : response.status).json({ error: "Hubtel refund was not accepted", status, details: data });
    }

    return res.json({
      ok: true,
      status,
      checkout_id: orderId,
      reference: payload.reference,
      callback_url: callback,
      raw: data,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/webhooks/hubtel/refund", async (req, res) => {
  try {
    const payload = req.body || {};
    const data = payload?.Data ?? payload?.data ?? {};
    const orderId =
      data.OrderId ??
      data.orderId ??
      payload.OrderId ??
      payload.orderId ??
      null;
    const status = mapHubtelRefundStatus(payload);

    let payment = null;
    if (orderId != null) {
      const { data: paymentRow } = await supabase
        .from("payments")
        .select("*")
        .eq("collection_external_id", String(orderId))
        .maybeSingle();
      payment = paymentRow || null;
    }

    await postSignedSupabaseWebhook("hubtel-refund-webhook", {
      refund_id: null,
      payment_id: payment?.id || null,
      shift_id: payment?.shift_id || null,
      checkout_id: orderId != null ? String(orderId) : null,
      reference: payment?.collection_reference || null,
      amount: Number(data.amount ?? data.Amount ?? payment?.amount ?? 0),
      currency: payment?.currency || "GHS",
      reason: "hubtel_refund_callback",
      provider: "hubtel",
      status: status === "processing" ? "failed" : status,
      raw: payload,
    });

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

app.post("/webhooks/hubtel/transfer", async (req, res) => {
  try {
    const signature = req.header("x-hubtel-signature");
    if (process.env.HUBTEL_WEBHOOK_SECRET && signature) {
      const body = JSON.stringify(req.body);
      const expected = crypto.createHmac("sha256", process.env.HUBTEL_WEBHOOK_SECRET).update(body).digest("hex");
      if (expected !== signature) return res.status(401).json({ error: "Invalid signature" });
    }

    const payload = req.body || {};
    const data = payload.Data || payload.data || {};
    const reference = data.ClientReference || data.clientReference || payload.ClientReference || payload.clientReference;
    if (!reference) return res.status(400).json({ error: "Transfer ClientReference missing" });

    const { data: payment, error } = await supabase
      .from("payments")
      .select("*")
      .eq("hubtel_transfer_reference", String(reference))
      .maybeSingle();
    if (error) throw error;
    if (!payment) return res.json({ ok: true, matched: false });

    const transferStatus = mapBalanceTransferStatus(payload);
    const externalId = data.id || data.Id || payment.hubtel_transfer_external_id || null;
    const failureReason = transferStatus === "failed" ? transferFailureReason(payload) : null;
    await updatePaymentWithOptionalFields({ id: payment.id }, {
      status: transferStatus === "failed" ? "failed" : "processing",
      hubtel_transfer_status: transferStatus,
      hubtel_transfer_external_id: externalId != null ? String(externalId) : null,
      hubtel_transfer_checked_at: new Date().toISOString(),
      hubtel_transfer_completed_at: transferStatus === "transferred" ? new Date().toISOString() : null,
      hubtel_transfer_failure_reason: failureReason,
    });

    if (transferStatus === "transferred") {
      const { data: refreshedPayment } = await supabase.from("payments").select("*").eq("id", payment.id).maybeSingle();
      await initiateWorkerPayoutAfterTransfer(refreshedPayment || payment);
    }

    return res.json({ ok: true, status: transferStatus });
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
    const paymentDetails = data?.PaymentDetails ?? data?.paymentDetails ?? {};
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
      await updatePaymentWithOptionalFields({ id: collectionPayment.id }, {
        status: collectionStatus,
        collection_external_id: transactionId != null ? String(transactionId) : collectionPayment.collection_external_id,
        collection_payment_method: paymentDetails?.PaymentType ?? paymentDetails?.paymentType ?? null,
        collection_payment_channel: paymentDetails?.Channel ?? paymentDetails?.channel ?? null,
      });

      if (collectionStatus === "captured" && collectionPayment.collection_provider === "hubtel_checkout_setup" && collectionPayment.venue_user_id) {
        await markVenueBillingConnected(collectionPayment.venue_user_id);
        return res.json({ ok: true });
      }

      if (collectionStatus === "captured" && collectionPayment.payout_provider === "profile_promotion" && collectionPayment.worker_user_id) {
        await markWorkerProfilePromoted(collectionPayment);
        return res.json({ ok: true });
      }

      if (collectionStatus === "captured" && collectionPayment.worker_user_id && Number(collectionPayment.worker_payout) > 0) {
        await updatePaymentWithOptionalFields({ id: collectionPayment.id }, {
          status: "captured",
          payout_provider: collectionPayment.payout_provider || "hubtel_disbursement",
          hubtel_transfer_status: collectionPayment.hubtel_transfer_reference ? collectionPayment.hubtel_transfer_status || "processing" : "pending",
          hubtel_transfer_amount: Number(collectionPayment.worker_payout),
          hubtel_transfer_checked_at: null,
          hubtel_transfer_failure_reason: null,
        });
        scheduleHubtelPayoutFunding(collectionPayment.id);
      }

      return res.json({ ok: true });
    }

    if (clientReference) {
      const { data: promotionRow } = await supabase
        .from("profile_promotions")
        .select("*")
        .eq("provider", "hubtel")
        .eq("external_id", `hubtel:${String(clientReference)}`)
        .maybeSingle();
      if (promotionRow) {
        const collectionStatus = mapHubtelCollectionStatus(payload);
        await updateProfilePromotionWithOptionalFields({ id: promotionRow.id }, {
          status: collectionStatus,
          checkout_id: transactionId != null ? String(transactionId) : promotionRow.checkout_id || null,
        });
        if (collectionStatus === "captured") {
          const promotedUntil = new Date();
          promotedUntil.setDate(promotedUntil.getDate() + 7);
          await supabase.from("workers").update({ promoted_until: promotedUntil.toISOString() }).eq("user_id", promotionRow.worker_user_id);
          await updateProfilePromotionWithOptionalFields({ id: promotionRow.id }, { promoted_until: promotedUntil.toISOString() });
        }
        return res.json({ ok: true });
      }
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
            await markVenueBillingConnected(setupPayment.venue_user_id);
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
