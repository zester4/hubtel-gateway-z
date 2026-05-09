/**
 * verify.js — Hubtel Ghana Card Verification
 *
 * Consumes the `GhanaCardData` extracted by scan.ts and calls the
 * Hubtel Verification API to validate the card and get a name-match score.
 *
 * Designed to be called from:
 *  - A Supabase Edge Function (server-side, keeps credentials safe)
 *  - Any Node.js / Deno / browser environment with fetch available
 *
 * Usage:
 *   import { verifyGhanaCard } from "./verify.js";
 *
 *   const result = await verifyGhanaCard(scan.data, {
 *     collectionAccountNumber: process.env.HUBTEL_ACCOUNT_NUMBER,
 *     basicAuthToken: process.env.HUBTEL_AUTH_TOKEN,
 *   });
 */

// ─────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────

const HUBTEL_BASE_URL = "https://rnv.hubtel.com/v2/merchantaccount/merchants";

/** Response codes returned by Hubtel */
export const HUBTEL_RESPONSE_CODES = {
  SUCCESS: "0000",
  NOT_FOUND: "3000",
};

// ─────────────────────────────────────────────────────────────
// TYPES (JSDoc — compatible with TypeScript consumers)
// ─────────────────────────────────────────────────────────────

/**
 * @typedef {Object} HubtelConfig
 * @property {string|number} collectionAccountNumber  - Your Hubtel Collection Account Number
 * @property {string}        basicAuthToken           - Base64-encoded Basic Auth token from Hubtel dashboard
 */

/**
 * @typedef {Object} VerifyGhanaCardResult
 * @property {boolean}      success        - true when Hubtel confirmed the card is valid
 * @property {boolean|null} isValid        - raw isValid value from Hubtel (null on network/API error)
 * @property {string|null}  score          - name match score e.g. "100%" (null on error)
 * @property {string}       responseCode   - Hubtel response code e.g. "0000"
 * @property {string}       message        - Human-readable status from Hubtel
 * @property {string|null}  error          - Error message if the request itself failed
 * @property {Object|null}  raw            - Full raw Hubtel response body
 */

// ─────────────────────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────────────────────

/**
 * verifyGhanaCard
 * ---------------
 * Sends the scanned Ghana Card data to Hubtel for validation.
 *
 * @param {import("./scan").GhanaCardData} cardData
 *   The `.data` object from scan.ts's ScanResult.
 *   Shape: { ghanaCardNumber, surname, firstnames, gender, dateOfBirth }
 *
 * @param {HubtelConfig} config
 *   Your Hubtel credentials. Keep these server-side (Supabase Edge Function).
 *
 * @returns {Promise<VerifyGhanaCardResult>}
 */
export async function verifyGhanaCard(cardData, config) {
  // ── 1. Guard: require a successful scan before calling Hubtel ──────────
  if (!cardData) {
    return _errorResult("No card data provided. Run scanCard() first and ensure it succeeded.");
  }

  const { ghanaCardNumber, surname, firstnames, gender, dateOfBirth } = cardData;

  const missing = [];
  if (!ghanaCardNumber) missing.push("ghanaCardNumber");
  if (!surname)         missing.push("surname");
  if (!firstnames)      missing.push("firstnames");
  if (!gender)          missing.push("gender");
  if (!dateOfBirth)     missing.push("dateOfBirth");

  if (missing.length > 0) {
    return _errorResult(`Missing required fields from scan: ${missing.join(", ")}`);
  }

  if (!config?.collectionAccountNumber) {
    return _errorResult("Hubtel collectionAccountNumber is required in config.");
  }

  if (!config?.basicAuthToken) {
    return _errorResult("Hubtel basicAuthToken is required in config.");
  }

  // ── 2. Build the request ───────────────────────────────────────────────
  const endpoint = `${HUBTEL_BASE_URL}/${config.collectionAccountNumber}/ghanacard/verify`;

  const payload = {
    ghanaCardNumber,          // "GHA-000000000-0"  — from scan.ts
    surname,                  // "DOE"
    firstnames,               // "JOHN"
    gender,                   // "male" | "female"
    dateOfBirth,              // "dd/mm/yyyy"       — already normalised by scan.ts
  };

  // ── 3. Call Hubtel ─────────────────────────────────────────────────────
  let rawResponse;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // Hubtel expects Basic <base64(API_ID:API_KEY)>.
        Authorization: `Basic ${String(config.basicAuthToken).replace(/^Basic\s+/i, "")}`,
      },
      body: JSON.stringify(payload),
    });

    rawResponse = await response.json();
  } catch (networkError) {
    return _errorResult(`Network error contacting Hubtel: ${networkError.message}`);
  }

  // ── 4. Parse and normalise the response ───────────────────────────────
  return _parseHubtelResponse(rawResponse);
}

// ─────────────────────────────────────────────────────────────
// VOTER ID VARIANT (bonus — same pattern, different endpoint)
// ─────────────────────────────────────────────────────────────

/**
 * verifyVoterId
 * -------------
 * Validates a Voter ID card via Hubtel.
 * Use this if your user provides a Voter ID instead of a Ghana Card.
 *
 * @param {Object} voterData
 * @param {string} voterData.voterIdCardNumber  e.g. "6161012342"
 * @param {string} voterData.surname
 * @param {string} voterData.othernames
 * @param {string} voterData.sex                "male" | "female"
 * @param {string} voterData.dateOfBirth        "yyyy/mm/dd"  ← NOTE: different format from Ghana Card
 *
 * @param {HubtelConfig} config
 * @returns {Promise<VerifyGhanaCardResult>}
 */
export async function verifyVoterId(voterData, config) {
  if (!voterData) {
    return _errorResult("No voter ID data provided.");
  }

  const { voterIdCardNumber, surname, othernames, sex, dateOfBirth } = voterData;

  const missing = [];
  if (!voterIdCardNumber) missing.push("voterIdCardNumber");
  if (!surname)           missing.push("surname");
  if (!othernames)        missing.push("othernames");
  if (!sex)               missing.push("sex");
  if (!dateOfBirth)       missing.push("dateOfBirth");

  if (missing.length > 0) {
    return _errorResult(`Missing required voter ID fields: ${missing.join(", ")}`);
  }

  if (!config?.collectionAccountNumber || !config?.basicAuthToken) {
    return _errorResult("Hubtel collectionAccountNumber and basicAuthToken are required.");
  }

  const endpoint = `${HUBTEL_BASE_URL}/${config.collectionAccountNumber}/voteridcard/verify`;

  let rawResponse;
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${String(config.basicAuthToken).replace(/^Basic\s+/i, "")}`,
      },
      body: JSON.stringify({ voterIdCardNumber, surname, othernames, sex, dateOfBirth }),
    });

    rawResponse = await response.json();
  } catch (networkError) {
    return _errorResult(`Network error contacting Hubtel: ${networkError.message}`);
  }

  return _parseHubtelResponse(rawResponse);
}

// ─────────────────────────────────────────────────────────────
// INTERNAL HELPERS
// ─────────────────────────────────────────────────────────────

/**
 * Normalises any Hubtel response into a consistent shape
 * for Supabase to store and the frontend to consume.
 *
 * @param {Object} body  - Parsed JSON from Hubtel
 * @returns {VerifyGhanaCardResult}
 */
function _parseHubtelResponse(body) {
  // Handle completely unexpected shapes
  if (!body || typeof body !== "object") {
    return _errorResult("Unexpected response format from Hubtel.");
  }

  const responseCode = body.responseCode ?? "unknown";
  const message      = body.message      ?? "No message";
  const isValid      = body.data?.isValid ?? null;
  const score        = body.data?.score   ?? null;

  return {
    success:      responseCode === HUBTEL_RESPONSE_CODES.SUCCESS && isValid === true,
    isValid,
    score,
    responseCode,
    message,
    error:        null,
    raw:          body,
  };
}

/**
 * Builds a failed result for pre-flight or network errors
 * (i.e. we never reached Hubtel).
 *
 * @param {string} errorMessage
 * @returns {VerifyGhanaCardResult}
 */
function _errorResult(errorMessage) {
  return {
    success:      false,
    isValid:      null,
    score:        null,
    responseCode: "CLIENT_ERROR",
    message:      "Verification request failed before reaching Hubtel.",
    error:        errorMessage,
    raw:          null,
  };
}
