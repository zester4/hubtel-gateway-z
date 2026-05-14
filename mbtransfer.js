import crypto from "crypto";

function normalizeBasicAuth(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.toLowerCase().startsWith("basic ") ? raw : `Basic ${raw}`;
}

function authHeader() {
  const explicit = normalizeBasicAuth(process.env.HUBTEL_TRANSFER_BASIC_AUTH || process.env.HUBTEL_BALANCE_TRANSFER_BASIC_AUTH);
  if (explicit) return explicit;

  const clientId =
    process.env.HUBTEL_TRANSFER_API_ID ||
    process.env.HUBTEL_TRANSFER_CLIENT_ID ||
    process.env.HUBTEL_DISBURSEMENT_API_ID ||
    process.env.HUBTEL_DISBURSEMENT_CLIENT_ID ||
    process.env.HUBTEL_API_ID ||
    process.env.HUBTEL_CLIENT_ID;
  const clientSecret =
    process.env.HUBTEL_TRANSFER_API_KEY ||
    process.env.HUBTEL_TRANSFER_CLIENT_SECRET ||
    process.env.HUBTEL_DISBURSEMENT_API_KEY ||
    process.env.HUBTEL_DISBURSEMENT_CLIENT_SECRET ||
    process.env.HUBTEL_API_KEY ||
    process.env.HUBTEL_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error("Hubtel balance transfer credentials are missing");
  }
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function transferBaseUrl() {
  return (process.env.HUBTEL_TRANSFER_BASE_URL || "https://trnf.hubtel.com").replace(/\/$/, "");
}

function transferReference(value) {
  const raw = String(value || "").trim();
  if (!raw) return `zt_${crypto.randomBytes(16).toString("hex").slice(0, 33)}`;
  if (raw.length <= 36) return raw;
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 36);
}

function amount(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error("Transfer amount must be greater than zero");
  return Math.round(parsed * 100) / 100;
}

async function hubtelJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: authHeader(),
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}

export function mapBalanceTransferStatus(payload = {}) {
  const data = payload.Data || payload.data || {};
  const rc = String(payload.ResponseCode ?? payload.responseCode ?? payload.code ?? "").trim().toLowerCase();
  const values = [
    payload.Message,
    payload.message,
    payload.status,
    payload.Status,
    data.status,
    data.Status,
    data.message,
    data.Message,
    data.failureReason,
    data.FailureReason,
  ].map((value) => String(value ?? "").trim().toLowerCase()).filter(Boolean);
  const text = values.join(" ");

  if (rc === "0000" || values.includes("success") || text.includes("success")) return "transferred";
  if (rc === "0001" || values.includes("pending") || text.includes("pending") || text.includes("processing")) return "processing";
  if (rc === "4000" || rc === "401" || values.includes("failed") || text.includes("fail") || text.includes("low balance")) return "failed";
  if (rc && rc !== "200") return "failed";
  return "processing";
}

export function transferFailureReason(payload = {}) {
  const data = payload.Data || payload.data || {};
  return data.failureReason || data.FailureReason || payload.Message || payload.message || null;
}

export async function getCollectionBalance({ collectionAccount }) {
  if (!collectionAccount) throw new Error("Collection account number is required");
  const url = `${transferBaseUrl()}/api/inter-transfers/${encodeURIComponent(collectionAccount)}`;
  return hubtelJson(url, { method: "GET" });
}

export async function getDisbursementBalance({ disbursementAccount }) {
  if (!disbursementAccount) throw new Error("Disbursement account number is required");
  const url = `${transferBaseUrl()}/api/inter-transfers/prepaid/${encodeURIComponent(disbursementAccount)}`;
  return hubtelJson(url, { method: "GET" });
}

export async function initiateBalanceTransfer({
  collectionAccount,
  disbursementAccount,
  value,
  reference,
  callbackUrl,
  description,
}) {
  if (!collectionAccount) throw new Error("Collection account number is required");
  if (!disbursementAccount) throw new Error("Disbursement account number is required");
  if (!callbackUrl) throw new Error("Hubtel balance transfer callback URL is required");

  const clientReference = transferReference(reference);
  const body = {
    Description: String(description || "ZiloShift worker payout funding").slice(0, 120),
    Amount: amount(value),
    ClientReference: clientReference,
    DestinationAccountNumber: String(disbursementAccount),
    PrimaryCallbackUrl: callbackUrl,
  };
  const url = `${transferBaseUrl()}/api/inter-transfers/${encodeURIComponent(collectionAccount)}`;
  const result = await hubtelJson(url, { method: "POST", body: JSON.stringify(body) });
  return { ...result, clientReference };
}

export async function checkBalanceTransferStatus({ collectionAccount, reference }) {
  if (!collectionAccount) throw new Error("Collection account number is required");
  if (!reference) throw new Error("Transfer clientReference is required");
  const url = new URL(`${transferBaseUrl()}/api/inter-transfers/status/${encodeURIComponent(collectionAccount)}`);
  url.searchParams.set("clientReference", String(reference));
  return hubtelJson(url.toString(), { method: "GET" });
}
