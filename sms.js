const DEFAULT_SMS_BASE_URL = "https://sms.hubtel.com";

function normalizeBasicAuth(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  return raw.toLowerCase().startsWith("basic ") ? raw : `Basic ${raw}`;
}

function smsAuthHeader() {
  const basic = normalizeBasicAuth(process.env.HUBTEL_SMS_BASIC_AUTH);
  if (basic) return basic;

  const clientId =
    process.env.HUBTEL_SMS_CLIENT_ID ||
    process.env.HUBTEL_SMS_API_ID ||
    process.env.HUBTEL_CLIENT_ID ||
    process.env.HUBTEL_API_ID;
  const clientSecret =
    process.env.HUBTEL_SMS_CLIENT_SECRET ||
    process.env.HUBTEL_SMS_API_KEY ||
    process.env.HUBTEL_CLIENT_SECRET ||
    process.env.HUBTEL_API_KEY;

  if (!clientId || !clientSecret) {
    throw new Error("Hubtel SMS credentials missing. Set HUBTEL_SMS_CLIENT_ID and HUBTEL_SMS_CLIENT_SECRET.");
  }

  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

function smsBaseUrl() {
  return String(process.env.HUBTEL_SMS_BASE_URL || DEFAULT_SMS_BASE_URL).replace(/\/$/, "");
}

function senderId(input) {
  const from = String(input || process.env.HUBTEL_SMS_SENDER_ID || "ZiloShift").trim();
  if (!from) throw new Error("SMS sender ID is required");
  return from.slice(0, 11);
}

export function normalizeGhanaMsisdn(value) {
  const digits = String(value || "").replace(/\D/g, "");
  if (!digits) return "";
  if (digits.startsWith("233") && digits.length >= 12) return digits;
  if (digits.startsWith("0") && digits.length === 10) return `233${digits.slice(1)}`;
  if (digits.length === 9) return `233${digits}`;
  return digits;
}

async function hubtelSmsRequest(path, payload) {
  const response = await fetch(`${smsBaseUrl()}${path}`, {
    method: "POST",
    headers: {
      Authorization: smsAuthHeader(),
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    const error = new Error("Hubtel SMS request failed");
    error.status = response.status;
    error.details = data;
    error.payload = {
      ...payload,
      Content: payload?.Content ? `[${String(payload.Content).length} chars]` : undefined,
      personalizedRecipients: Array.isArray(payload?.personalizedRecipients)
        ? `${payload.personalizedRecipients.length} recipients`
        : undefined,
    };
    throw error;
  }
  if (data && typeof data === "object" && data.status != null && Number(data.status) !== 0) {
    const error = new Error(data.statusDescription || "Hubtel SMS was not accepted");
    error.status = 400;
    error.details = data;
    error.payload = {
      ...payload,
      Content: payload?.Content ? `[${String(payload.Content).length} chars]` : undefined,
      personalizedRecipients: Array.isArray(payload?.personalizedRecipients)
        ? `${payload.personalizedRecipients.length} recipients`
        : undefined,
    };
    throw error;
  }
  return data;
}

async function hubtelSmsStatusRequest(path) {
  const response = await fetch(`${smsBaseUrl()}${path}`, {
    method: "GET",
    headers: {
      Authorization: smsAuthHeader(),
      Accept: "application/json",
    },
  });
  const text = await response.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    const error = new Error("Hubtel SMS status request failed");
    error.status = response.status;
    error.details = data;
    throw error;
  }
  return data;
}

export async function sendSms({ to, content, from }) {
  const recipient = normalizeGhanaMsisdn(to);
  if (!recipient) throw new Error("SMS recipient is required");
  const message = String(content || "").trim();
  if (!message) throw new Error("SMS content is required");

  return hubtelSmsRequest("/v1/messages/send", {
    From: senderId(from),
    To: recipient,
    Content: message.slice(0, 918),
  });
}

export async function sendPersonalizedSms({ recipients, from }) {
  const personalizedRecipients = (Array.isArray(recipients) ? recipients : [])
    .map((row) => ({
      To: normalizeGhanaMsisdn(row?.to),
      Content: String(row?.content || "").trim().slice(0, 918),
    }))
    .filter((row) => row.To && row.Content);

  if (!personalizedRecipients.length) throw new Error("At least one personalized SMS recipient is required");

  return hubtelSmsRequest("/v1/messages/batch/personalized/send", {
    From: senderId(from),
    personalizedRecipients,
  });
}

export async function getSmsStatus(messageId) {
  const id = String(messageId || "").trim();
  if (!id) throw new Error("messageId is required");
  return hubtelSmsStatusRequest(`/v1/messages/${encodeURIComponent(id)}`);
}

export async function getSmsBatchStatus(batchId) {
  const id = String(batchId || "").trim();
  if (!id) throw new Error("batchId is required");
  return hubtelSmsStatusRequest(`/v1/messages/batch/${encodeURIComponent(id)}`);
}

export function smsDiagnostics() {
  return {
    sms_configured: Boolean(
      process.env.HUBTEL_SMS_BASIC_AUTH ||
      (process.env.HUBTEL_SMS_CLIENT_ID && process.env.HUBTEL_SMS_CLIENT_SECRET) ||
      (process.env.HUBTEL_SMS_API_ID && process.env.HUBTEL_SMS_API_KEY) ||
      (process.env.HUBTEL_CLIENT_ID && process.env.HUBTEL_CLIENT_SECRET) ||
      (process.env.HUBTEL_API_ID && process.env.HUBTEL_API_KEY)
    ),
    sms_sender_id: senderId(),
    sms_base_url: smsBaseUrl(),
  };
}
