# ZiloShift Hubtel Gateway (ORACLE CLOUD)

Use this service for Ghana-only Hubtel payout calls from a static-whitelisted `/32` server IP.

COMMANDS: pm2 restart hubtel-gateway --update-env
~/deploy.sh

## Why this exists

- Supabase Edge Functions do not provide a fixed outbound IP for Hubtel whitelist requirements.
- ORACLE CLOUD service with static egress IP can be whitelisted by Hubtel.

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
- `POST /api/checkout/initiate` (Hubtel Checkout; dedupes shift checkouts for 30 minutes)
- `POST /api/checkout/refund` (Hubtel Checkout refund; requires `checkout_id` or `reference`; cash/cheque reversal uses `HUBTEL_POS_REVERSAL_URL`)
- `GET /api/meta/payout-options` (momo channels + banks list)
- `GET /api/verify-momo-account?channel=mtn-gh&phone=233...` (MoMo account name check; requires `x-gateway-token`)
- `POST /api/verify-bank-account` (account-name verification; requires `x-gateway-token`)
- `POST /webhooks/hubtel` (Hubtel status callback)
- `POST /webhooks/hubtel/refund` (Hubtel refund callback; forwards signed status to `hubtel-refund-webhook`)

## Security

- `x-gateway-token` required for internal disbursement calls.
- Gateway-to-Supabase refund callbacks require `HUBTEL_WEBHOOK_SECRET` and include `x-signature`, an HMAC-SHA256 of the JSON body.
- Hubtel callback HMAC verification remains supported with `x-hubtel-signature` when Hubtel is configured to send it.
