# ZiloShift Hubtel Gateway (Render/Railway)

Use this service for Ghana-only Hubtel payout calls from a static-whitelisted `/32` server IP.

## Why this exists

- Supabase Edge Functions do not provide a fixed outbound IP for Hubtel whitelist requirements.
- Render/Railway service with static egress IP can be whitelisted by Hubtel.

## Deploy

1. Deploy this folder as a Node service (`npm install`, `npm start`).
2. Set environment variables from `.env.example`.
3. Ask Hubtel to whitelist your deployed public IP (`/32`).
4. Set in Supabase secrets:
   - `HUBTEL_GATEWAY_URL=https://<your-service-domain>`
   - `HUBTEL_GATEWAY_TOKEN=<same as HUBTEL_GATEWAY_TOKEN>`

## Hubtel Credentials

`HUBTEL_API_ID` and `HUBTEL_API_KEY` are used as the fallback Basic Auth pair for Hubtel Sales APIs.
Legacy `HUBTEL_CLIENT_ID` and `HUBTEL_CLIENT_SECRET` still work, but Hubtel's Sales docs call these values API ID/API Key.
If Hubtel gives separate API credentials/scopes, set the product-specific values instead:

- `HUBTEL_CHECKOUT_*` for Online Checkout and checkout transaction status.
- `HUBTEL_DIRECT_DEBIT_*` for Direct Debit preapproval and charge.
- `HUBTEL_RNV_*` for MoMo account-name verification.
- `HUBTEL_DISBURSEMENT_*` for send money/send-to-bank payouts.

Each product supports either `*_API_ID` + `*_API_KEY` or `*_BASIC_AUTH`.
`*_BASIC_AUTH` may be the base64 token alone or the full `Basic <token>` header value.

## Endpoints

- `GET /health`
- `POST /api/disburse` (called by Supabase function)
- `GET /api/meta/payout-options` (momo channels + banks list)
- `GET /api/verify-momo-account?channel=mtn-gh&phone=233...` (MoMo account name check; requires `x-gateway-token`)
- `POST /api/verify-bank-account` (account-name verification; requires `x-gateway-token`)
- `POST /webhooks/hubtel` (Hubtel status callback)

## Security

- `x-gateway-token` required for internal disbursement calls.
- Optional webhook HMAC verification with `HUBTEL_WEBHOOK_SECRET`.
