import express from "express";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const router = express.Router();

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

function assertSupabaseAdminConfigured() {
  const key = String(process.env.SUPABASE_SERVICE_ROLE_KEY || "");
  if (!process.env.SUPABASE_URL || !key) {
    throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
  }
  if (key.startsWith("sb_publishable_") || key.startsWith("sb_anon_")) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY must be a secret/service-role key, not a publishable/anon key");
  }
}

function requireGatewayToken(req, res, next) {
  const token = req.header("x-gateway-token");
  const expected = process.env.HUBTEL_GATEWAY_TOKEN || process.env.GATEWAY_TOKEN;
  if (!expected || token !== expected) return res.status(401).json({ error: "Unauthorized gateway request" });
  next();
}

function normalizeBasicAuth(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.toLowerCase().startsWith("basic ") ? raw : `Basic ${raw}`;
}

function hubtelAuthHeader(scope = "HUBTEL_CHECKOUT") {
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
  if (!clientId || !clientSecret) throw new Error("Hubtel Checkout credentials are not configured");
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function checkoutBaseUrl() {
  return String(process.env.HUBTEL_CHECKOUT_BASE_URL || "https://payproxyapi.hubtel.com").replace(/\/$/, "");
}

function statusBaseUrl() {
  return String(process.env.HUBTEL_TXN_STATUS_BASE_URL || "https://api-txnstatus.hubtel.com").replace(/\/$/, "");
}

function collectionAccount() {
  const account = process.env.HUBTEL_MERCHANT_ACCOUNT_NUMBER || process.env.HUBTEL_ACCOUNT_NUMBER;
  if (!account) throw new Error("HUBTEL_MERCHANT_ACCOUNT_NUMBER is required");
  return account;
}

function callbackUrl() {
  const explicit = process.env.HUBTEL_PROMO_CALLBACK_URL;
  if (explicit) return explicit;
  const sharedCallback = process.env.HUBTEL_CALLBACK_URL || process.env.HUBTEL_PREAUTH_CALLBACK_URL;
  if (sharedCallback) return sharedCallback;
  throw new Error("Set HUBTEL_PROMO_CALLBACK_URL or HUBTEL_CALLBACK_URL for profile promotion callbacks");
}

function clientReference(ref) {
  const value = String(ref || "").trim();
  if (!value) return crypto.randomBytes(16).toString("hex").slice(0, 32);
  if (value.length <= 32) return value;
  return crypto.createHash("sha256").update(value).digest("base64url").replace(/=/g, "").slice(0, 32);
}

function normalizeGhMsisdn(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.startsWith("233")) return digits;
  if (digits.startsWith("0") && digits.length === 10) return `233${digits.slice(1)}`;
  if (digits.length === 9) return `233${digits}`;
  return digits;
}

function checkoutResult(payload, fallbackReference) {
  const data = payload?.data || payload?.Data || payload || {};
  return {
    checkout_url: data.checkoutUrl || data.CheckoutUrl || payload?.checkout_url || payload?.CheckoutUrl || null,
    checkout_direct_url: data.checkoutDirectUrl || data.CheckoutDirectUrl || payload?.checkout_direct_url || null,
    checkout_id: data.checkoutId || data.CheckoutId || payload?.checkout_id || null,
    reference: data.clientReference || data.ClientReference || payload?.reference || fallbackReference,
    raw: payload,
  };
}

function mapHubtelCollectionStatus(payload) {
  const data = payload?.Data || payload?.data || payload || {};
  const statusText = String(
    data.Status ||
      data.status ||
      data.TransactionStatus ||
      data.transactionStatus ||
      payload?.Status ||
      payload?.status ||
      "",
  ).toLowerCase();
  const responseCode = String(payload?.ResponseCode || payload?.responseCode || data.ResponseCode || data.responseCode || "");
  if (["failed", "cancelled", "canceled", "declined", "rejected"].some((word) => statusText.includes(word))) return "failed";
  if (responseCode === "0000" || ["success", "paid", "captured", "completed", "approved"].some((word) => statusText.includes(word))) return "captured";
  return "processing";
}

function extractCallbackIds(payload) {
  const data = payload?.Data || payload?.data || {};
  return {
    clientReference:
      data.ClientReference ||
      data.clientReference ||
      payload.ClientReference ||
      payload.clientReference ||
      payload.ClientReferenceId ||
      payload.clientReferenceId ||
      null,
    checkoutId:
      data.CheckoutId ||
      data.checkoutId ||
      data.TransactionId ||
      data.transactionId ||
      payload.CheckoutId ||
      payload.checkoutId ||
      payload.TransactionId ||
      payload.transactionId ||
      null,
    paymentMethod: data?.PaymentDetails?.PaymentType || data?.paymentDetails?.paymentType || null,
    paymentChannel: data?.PaymentDetails?.Channel || data?.paymentDetails?.channel || null,
  };
}

async function updatePromotionWithOptionalFields(matcher, patch) {
  const { error } = await supabase.from("profile_promotions").update(patch).match(matcher);
  if (error?.code === "42703" || error?.code === "PGRST204") {
    const fallback = { ...patch };
    delete fallback.checkout_url;
    delete fallback.checkout_direct_url;
    delete fallback.checkout_id;
    delete fallback.status;
    delete fallback.promoted_until;
    const { error: fallbackError } = await supabase.from("profile_promotions").update(fallback).match(matcher);
    if (fallbackError) throw fallbackError;
  } else if (error) {
    throw error;
  }
}

async function insertPromotionWithOptionalFields(patch) {
  const { data, error } = await supabase.from("profile_promotions").insert(patch).select("*").single();
  if (error?.code === "42703" || error?.code === "PGRST204") {
    const fallback = { ...patch };
    delete fallback.checkout_url;
    delete fallback.checkout_direct_url;
    delete fallback.checkout_id;
    delete fallback.status;
    delete fallback.promoted_until;
    const fallbackRes = await supabase.from("profile_promotions").insert(fallback).select("*").single();
    if (fallbackRes.error) throw fallbackRes.error;
    return fallbackRes.data;
  }
  if (error) throw error;
  return data;
}

async function markPromoted(row) {
  if (!row?.worker_user_id) throw new Error("Promotion row has no worker_user_id");
  const promotedUntil = new Date();
  promotedUntil.setDate(promotedUntil.getDate() + 7);
  const promotedUntilIso = promotedUntil.toISOString();

  const { error: workerError } = await supabase
    .from("workers")
    .update({ promoted_until: promotedUntilIso })
    .eq("user_id", row.worker_user_id);
  if (workerError) throw workerError;

  await updatePromotionWithOptionalFields({ id: row.id }, {
    status: "captured",
    promoted_until: promotedUntilIso,
  });
  return promotedUntilIso;
}

async function lookupPromotion({ workerUserId, reference, checkoutId }) {
  let query = supabase
    .from("profile_promotions")
    .select("*")
    .eq("provider", "hubtel")
    .order("created_at", { ascending: false })
    .limit(1);
  if (reference) {
    const externalId = String(reference).startsWith("hubtel:") ? String(reference) : `hubtel:${reference}`;
    query = query.eq("external_id", externalId);
    if (workerUserId) query = query.eq("worker_user_id", workerUserId);
  } else if (checkoutId) {
    query = query.eq("checkout_id", checkoutId);
    if (workerUserId) query = query.eq("worker_user_id", workerUserId);
  } else if (workerUserId) {
    query = query.eq("worker_user_id", workerUserId);
  }
  const { data, error } = await query;
  if (error) throw error;
  return data?.[0] || null;
}

async function checkHubtelStatus({ reference, checkoutId }) {
  const account = collectionAccount();
  const url = new URL(`${statusBaseUrl()}/transactions/${encodeURIComponent(account)}/status`);
  if (reference) url.searchParams.set("clientReference", reference);
  if (checkoutId) url.searchParams.set("hubtelTransactionId", checkoutId);
  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), Accept: "application/json" },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error("Hubtel checkout status failed");
    error.status = response.status;
    error.details = payload;
    throw error;
  }
  return { status: mapHubtelCollectionStatus(payload), raw: payload };
}

router.post("/api/profile-promotion/checkout", requireGatewayToken, async (req, res) => {
  try {
    assertSupabaseAdminConfigured();
    const {
      reference,
      amount = "30.00",
      currency = "GHS",
      description = "ZiloShift profile promotion checkout",
      return_url,
      cancellation_url,
      worker_user_id,
      worker_id,
      payee_name = "ZiloShift Profile Promotion",
      payee_mobile_number,
      payee_email,
    } = req.body || {};

    if (!reference) return res.status(400).json({ error: "reference is required" });
    if (!worker_user_id) return res.status(400).json({ error: "worker_user_id is required" });
    if (!return_url) return res.status(400).json({ error: "return_url is required" });

    const amountNumber = Number(amount);
    if (!Number.isFinite(amountNumber) || amountNumber <= 0) return res.status(400).json({ error: "amount must be greater than zero" });

    const checkoutReference = clientReference(reference);
    const externalId = `hubtel:${checkoutReference}`;
    const existing = await lookupPromotion({ workerUserId: worker_user_id, reference: checkoutReference });
    if (existing) {
      return res.json({
        ok: true,
        deduped: true,
        promoted: existing.status === "captured",
        status: existing.status || "pending",
        checkout_url: existing.checkout_url || null,
        checkout_direct_url: existing.checkout_direct_url || null,
        checkout_id: existing.checkout_id || null,
        reference: checkoutReference,
        promoted_until: existing.promoted_until || null,
        message: "Existing Hubtel profile promotion session returned.",
      });
    }

    const body = {
      totalAmount: Number(amountNumber.toFixed(2)),
      description,
      callbackUrl: callbackUrl(),
      returnUrl: return_url,
      merchantAccountNumber: collectionAccount(),
      cancellationUrl: cancellation_url || return_url,
      clientReference: checkoutReference,
      payeeName: payee_name,
    };
    if (payee_mobile_number) body.payeeMobileNumber = normalizeGhMsisdn(payee_mobile_number);
    if (payee_email) body.payeeEmail = payee_email;

    const response = await fetch(`${checkoutBaseUrl()}/items/initiate`, {
      method: "POST",
      headers: { Authorization: hubtelAuthHeader("HUBTEL_CHECKOUT"), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json().catch(() => ({}));
    const responseCode = payload?.responseCode || payload?.ResponseCode;
    if (!response.ok) return res.status(response.status).json({ error: "Hubtel checkout init failed", details: payload });
    if (responseCode && responseCode !== "0000") {
      return res.status(400).json({ error: "Hubtel checkout did not return success", responseCode, details: payload });
    }

    const checkout = checkoutResult(payload, checkoutReference);
    await insertPromotionWithOptionalFields({
      worker_user_id,
      amount: amountNumber,
      currency: String(currency || "GHS").toUpperCase(),
      provider: "hubtel",
      external_id: externalId,
      stripe_session_id: null,
      status: "pending",
      checkout_url: checkout.checkout_url,
      checkout_direct_url: checkout.checkout_direct_url,
      checkout_id: checkout.checkout_id != null ? String(checkout.checkout_id) : null,
    });

    return res.json({
      ok: true,
      checkout_url: checkout.checkout_url,
      checkout_direct_url: checkout.checkout_direct_url,
      checkout_id: checkout.checkout_id,
      reference: checkoutReference,
      worker_id: worker_id || null,
      message: "Open Hubtel Checkout to promote your profile for 7 days.",
      raw: checkout.raw,
    });
  } catch (error) {
    console.error("[PROMO CHECKOUT]", error);
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null });
  }
});

router.get("/api/profile-promotion/status", requireGatewayToken, async (req, res) => {
  try {
    assertSupabaseAdminConfigured();
    const workerUserId = String(req.query.worker_user_id || req.query.workerUserId || "").trim();
    const reference = String(req.query.reference || "").trim();
    const checkoutId = String(req.query.checkout_id || req.query.checkoutid || "").trim();
    if (!workerUserId && !reference && !checkoutId) {
      return res.status(400).json({ error: "worker_user_id, reference, or checkout_id is required" });
    }

    const row = await lookupPromotion({ workerUserId, reference, checkoutId });
    if (!row) return res.json({ ok: true, promoted: false, status: "not_found" });

    const ref = String(row.external_id || "").replace(/^hubtel:/, "");
    if (row.status === "captured") {
      const promotedUntil = row.promoted_until || await markPromoted(row);
      return res.json({
        ok: true,
        promoted: true,
        status: "captured",
        reference: ref,
        checkout_id: row.checkout_id || checkoutId || null,
        promoted_until: promotedUntil,
      });
    }

    const checked = await checkHubtelStatus({ reference: ref || reference, checkoutId: row.checkout_id || checkoutId });
    await updatePromotionWithOptionalFields({ id: row.id }, {
      status: checked.status,
      checkout_id: row.checkout_id || checkoutId || null,
    });
    if (checked.status === "captured") {
      const promotedUntil = await markPromoted(row);
      return res.json({
        ok: true,
        promoted: true,
        status: "captured",
        reference: ref,
        checkout_id: row.checkout_id || checkoutId || null,
        promoted_until: promotedUntil,
        raw: checked.raw,
      });
    }

    return res.json({
      ok: true,
      promoted: false,
      status: checked.status,
      reference: ref,
      checkout_id: row.checkout_id || checkoutId || null,
      checkout_url: row.checkout_url || null,
      checkout_direct_url: row.checkout_direct_url || null,
      raw: checked.raw,
    });
  } catch (error) {
    console.error("[PROMO STATUS]", error);
    return res.status(error.status || 500).json({ error: error.message, details: error.details || null });
  }
});

router.post("/webhooks/hubtel/profile-promotion", async (req, res) => {
  try {
    const signature = req.header("x-hubtel-signature");
    if (process.env.HUBTEL_WEBHOOK_SECRET && signature) {
      const expected = crypto.createHmac("sha256", process.env.HUBTEL_WEBHOOK_SECRET).update(JSON.stringify(req.body)).digest("hex");
      if (expected !== signature) return res.status(401).json({ error: "Invalid signature" });
    }

    const payload = req.body || {};
    const ids = extractCallbackIds(payload);
    if (!ids.clientReference && !ids.checkoutId) return res.json({ ok: true, ignored: true });

    const row = await lookupPromotion({ reference: ids.clientReference, checkoutId: ids.checkoutId });
    if (!row) return res.json({ ok: true, promoted: false, status: "not_found" });

    const status = mapHubtelCollectionStatus(payload);
    await updatePromotionWithOptionalFields({ id: row.id }, {
      status,
      checkout_id: ids.checkoutId != null ? String(ids.checkoutId) : row.checkout_id || null,
    });
    if (status === "captured") {
      const promotedUntil = await markPromoted({ ...row, checkout_id: ids.checkoutId || row.checkout_id });
      return res.json({ ok: true, promoted: true, status, promoted_until: promotedUntil });
    }
    return res.json({ ok: true, promoted: false, status });
  } catch (error) {
    console.error("[PROMO WEBHOOK]", error);
    return res.status(500).json({ error: error.message });
  }
});

export default router;
