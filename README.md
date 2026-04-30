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
   - `HUBTEL_GATEWAY_TOKEN=<same as GATEWAY_TOKEN>`

## Endpoints

- `GET /health`
- `POST /api/disburse` (called by Supabase function)
- `POST /webhooks/hubtel` (Hubtel status callback)

## Security

- `x-gateway-token` required for internal disbursement calls.
- Optional webhook HMAC verification with `HUBTEL_WEBHOOK_SECRET`.
