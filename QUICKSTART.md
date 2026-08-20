# Agentblips Quickstart

Deploy the Hono worker, point x402 at your USDC wallet on Base, and open the live operator HUD on the same origin. Agent ingest keeps running after the free HUD allowance; the dashboard prompts you to subscribe at **5,000** tracked requests.

---

## 1. Deploy the worker (website owners)

This repo is a Cloudflare Worker. The API lives in `src/index.ts`. The HUD is static `public/index.html` served from the same origin.

### Prerequisites

- Node 18+
- A [Cloudflare](https://dash.cloudflare.com) account
- A **Base** address that can receive **USDC** (this is `X402_PAY_TO`)

```bash
npm install
npx wrangler login
```

### Create KV (usage, activity, owner meters)

```bash
npx wrangler kv namespace create USAGE_KV
```

Copy the namespace id into `wrangler.jsonc` under `kv_namespaces` (`binding`: `USAGE_KV`).

### Set payment and admin secrets

Never put the receiving wallet or admin key in `vars`. Use secrets:

```bash
# USDC on Base — checksummed 0x address that receives x402 settlements
npx wrangler secret put X402_PAY_TO

# Optional: fleet + subscription admin for the HUD
npx wrangler secret put ADMIN_SECRET
```

Optional durable log sink (ingest still succeeds if this is unset or times out):

```bash
npx wrangler secret put SUPABASE_URL
npx wrangler secret put SUPABASE_SERVICE_ROLE_KEY
```

### Price, network, and owner config

These are already in `wrangler.jsonc` `vars`. Change them before deploy:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TELEMETRY_PRICE` | `$0.001` | x402 price per paid blip (USDC) |
| `X402_NETWORK` | `base` | x402 network selector |
| `X402_FACILITATOR_URL` | `https://x402.org/facilitator` | Verify + settle |
| `FREE_TIER_LIMIT` | `100` | Free blips **per agent** before x402 |
| `PLATFORM_FREE_LIMIT` | `5000` | Free **tracked HUD** requests per owner |
| `OWNER_ID` | `default` | Site-owner / account id for platform metering |
| `SUBSCRIPTION_ACTIVE` | unset | Set `true` to keep the HUD live past 5,000 |

`SUBSCRIPTION_ACTIVE=true` can be added to `vars` or toggled at runtime with `POST /api/admin/owner` (`action: "subscribe"`).

### Deploy

```bash
npx wrangler deploy
```

Wrangler prints the Worker URL, for example `https://agentblips-core.<your-subdomain>.workers.dev`.

---

## 2. Connect the live operator HUD

Open the Worker origin in a browser. Non-`/api/*` routes serve `public/index.html`.

**[Your worker URL](https://agentblips-core.agentblips-spenser.workers.dev)** — replace with the URL from `wrangler deploy`.

The HUD polls:

- `GET /api/telemetry/overview` — fleet meters, USDC revenue, owner/platform quota
- `GET /api/telemetry/activity` — successful blips and 402 drop-offs

No SDK is required for the dashboard. Paste `ADMIN_SECRET` into **X-Admin-Key** in the header to reset agents, change per-agent free limits, block scrapers, or mark the workspace subscribed after 5,000 tracked requests.

### Config verification

After deploy, confirm:

1. `GET /api` returns `protocol: "x402"` and the endpoint list.
2. `GET /api/telemetry/overview` includes `platform.ownerId`, `platform.freeLimit` (5000), and `totals.revenueUsdc`.
3. A test `POST /api/telemetry` with `X-Agent-Id` returns `200` and a `blipId`.
4. The HUD at `/` shows that blip within a few seconds.
5. `X402_PAY_TO` is set — otherwise paid ingest returns `PAYMENT_CONFIG_MISSING` (500) after the per-agent free tier.

---

## 3. Site-owner tier (5,000 tracked requests)

Two meters exist. They do not replace each other.

| Meter | Scope | After the cap |
| --- | --- | --- |
| Per-agent `FREE_TIER_LIMIT` (100) | Each `X-Agent-Id` | HTTP **402** + x402 USDC on Base. Ingest continues once the agent pays. |
| Platform `PLATFORM_FREE_LIMIT` (5,000) | `OWNER_ID` / `X-Owner-Id` | Live HUD shows an upgrade notice. **Ingest and x402 keep working.** |

Successful ingest increments the owner’s `trackedBlips`. At 5,000 without an active subscription the HUD dims live feeds and asks you to upgrade. Activate with:

```bash
# Runtime (requires ADMIN_SECRET)
curl -X POST "$ENDPOINT/api/admin/owner" \
  -H "X-Admin-Key: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"action":"subscribe"}'

# Or persist at deploy
# wrangler.jsonc vars: "SUBSCRIPTION_ACTIVE": "true"
```

Optional header `X-Owner-Id` overrides `OWNER_ID` when one worker serves more than one account.

---

## 4. Install the agent client

The TypeScript SDK lives in this repository as `src/client.ts`.

```bash
npm install agentblips-core
# or, from a local checkout:
# npm install ./agentblips-core

npm install viem x402
```

```ts
import { AgentBlipsClient } from 'agentblips-core/src/client';
```

Inside this repo:

```ts
import { AgentBlipsClient } from './src/client';
```

Node 18+ (global `fetch`) or a Cloudflare Worker / modern browser runtime is required.

---

## 5. Initialize `AgentBlipsClient`

Every agent needs a **stable ID** (`X-Agent-Id`) and, for paid ingest, a **Base wallet** that can sign EIP-3009 `TransferWithAuthorization` payloads.

```ts
import { AgentBlipsClient } from 'agentblips-core/src/client';

const client = new AgentBlipsClient(
  'https://agentblips-core.agentblips-spenser.workers.dev',
  'my-agent-001',
  {
    privateKey: process.env.AGENT_WALLET_PRIVATE_KEY as `0x${string}`,
    network: 'base',
    autoRetryPayment: true, // default when a signer is present
  },
);
```

| Option | Purpose |
| --- | --- |
| `privateKey` | Hex key used to sign USDC authorizations on Base |
| `signer` | Pre-built viem `LocalAccount` (overrides `privateKey`) |
| `network` | x402 network selector; default `'base'` |
| `autoRetryPayment` | On HTTP 402, sign and retry with `X-PAYMENT` |

Without a signer, free-tier blips still ingest. Once the **per-agent** allowance is exhausted, `sendTelemetry()` returns a 402 challenge instead of settling automatically.

**Wallet requirements**

- Fund the **agent** address with **USDC on Base** (not ETH-only).
- Keep the key in an environment variable. Never commit it.
- Default price is **$0.001 USDC per blip** after the per-agent free tier (`TELEMETRY_PRICE`).

Check remaining allowance before you loop:

```ts
const status = await client.getStatus();
// usageCount, freeTierLimit, remainingFreeBlips, paymentRequired, pricePerBlip, network
```

---

## 6. Send telemetry blips

```ts
const result = await client.sendTelemetry('heartbeat', {
  step: 12,
  status: 'running',
});

if (result.ok) {
  console.log(result.data.blipId, result.data.billingMode); // 'free' | 'paid'
}
```

The worker expects JSON with a string `event` field. Payload is arbitrary JSON.

### Idempotency

Retries of the same logical blip must not double-count usage or re-trigger x402. Pass a **stable** `idempotencyKey`.

```ts
const result = await client.sendTelemetry(
  'tool.completed',
  { tool: 'search', durationMs: 840 },
  {
    idempotencyKey: 'run-42-step-12',
    timestamp: '2026-08-18T16:00:00.000Z',
  },
);

if (result.ok && result.data.idempotentReplay) {
  // Same key hit a cached 2xx within 60s — no extra usage, no extra payment
}
```

Rules:

- Header: `X-Idempotency-Key`.
- Cached successful responses live in KV for **60 seconds**.
- Duplicate keys in that window replay the original 200. 402/4xx/5xx are **not** cached, so a payment retry with the same key can still settle.
- If you omit the header, the worker hashes `agentId + timestamp + raw body`. Include `timestamp` if you want that fallback to be stable across retries.

`sendTelemetryOrThrow()` accepts the same options and throws `PaymentRequiredError` when auto-retry cannot settle.

---

## 7. Allowances and 402 challenges

### Per-agent free tier

Each agent gets **100 blips** (configurable via `FREE_TIER_LIMIT`). After that, ingest requires x402. This is independent of the 5,000-request HUD quota.

### Automated settlement (recommended)

With `privateKey` / `signer` set, the client:

1. POSTs the blip.
2. On **402**, reads `accepts` payment requirements.
3. Signs an EIP-3009 USDC authorization for Base.
4. Retries with `X-PAYMENT`.
5. Returns `{ ok: true, paidViaRetry: true, data }` on success.

```ts
const result = await client.sendTelemetry('heartbeat', { tick: 1 });

if (result.ok && result.paidViaRetry) {
  console.log('Settled on Base, blip ingested');
}
```

### Manual 402 handling

Disable auto-retry if you want to inspect or sign elsewhere:

```ts
const client = new AgentBlipsClient(ENDPOINT, AGENT_ID, {
  privateKey: process.env.AGENT_WALLET_PRIVATE_KEY as `0x${string}`,
  autoRetryPayment: false,
});

const result = await client.sendTelemetry('heartbeat', { tick: 1 });

if (!result.ok && result.paymentRequired) {
  const challenge = result.challenge;
  // challenge.accepts — x402 payment requirements
  // Retry yourself with header X-PAYMENT
}
```

### Custom allowances (operators)

Fleet admins can reset usage, raise the free-tier cap, or block an agent. Requires `ADMIN_SECRET` as `X-Admin-Key`.

```bash
# Raise this agent's free-tier limit
curl -X POST "$ENDPOINT/api/admin/agent" \
  -H "X-Admin-Key: $ADMIN_SECRET" \
  -H "X-Agent-Id: my-agent-001" \
  -H "Content-Type: application/json" \
  -d '{"action":"set_limit","freeTierLimit":500}'

# Reset usage back to zero
curl -X POST "$ENDPOINT/api/admin/agent" \
  -H "X-Admin-Key: $ADMIN_SECRET" \
  -H "X-Agent-Id: my-agent-001" \
  -H "Content-Type: application/json" \
  -d '{"action":"reset"}'
```

Actions: `reset` · `set_limit` · `block` · `unblock`.

The live HUD at `/` exposes the same controls when the admin key is entered in the dashboard.

---

## HTTP surface

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/` | Telemetry HUD |
| `GET` | `/api` | Discovery JSON |
| `GET` | `/api/telemetry/status` | Allowance for `X-Agent-Id` |
| `POST` | `/api/telemetry` | Ingest (`X-Agent-Id`, optional `X-PAYMENT`, `X-Idempotency-Key`, `X-Owner-Id`) |
| `GET` | `/api/telemetry/overview` | Fleet metrics + `platform` quota |
| `GET` | `/api/telemetry/activity` | Successful events + 402 rejections |
| `POST` | `/api/admin/agent` | Fleet admin (`X-Admin-Key` + `X-Agent-Id`) |
| `POST` | `/api/admin/owner` | Subscribe / unsubscribe / reset tracked (`X-Admin-Key`) |

Minimal curl (free tier):

```bash
curl -X POST https://agentblips-core.agentblips-spenser.workers.dev/api/telemetry \
  -H "Content-Type: application/json" \
  -H "X-Agent-Id: my-agent-001" \
  -H "X-Idempotency-Key: run-42-step-12" \
  -d '{"event":"heartbeat","payload":{"step":12}}'
```

---

## Failure codes worth handling

| Code | HTTP | Meaning |
| --- | --- | --- |
| `AGENT_ID_REQUIRED` | 401 | Missing `X-Agent-Id` |
| `AGENT_BLOCKED` | 403 | Operator blocked this agent |
| `FREE_TIER_EXHAUSTED` | 402 | Sign and retry with `X-PAYMENT` |
| `INVALID_PAYMENT` / `VERIFICATION_FAILED` / `SETTLEMENT_FAILED` | 402 | Payment header rejected |
| `INVALID_EVENT` | 400 | Body must include string `event` |
| `PAYMENT_CONFIG_MISSING` | 500 | `X402_PAY_TO` secret is not set |

Supabase and KV timeouts **do not** fail ingest. The worker returns `200` with `persisted: false` when the log sink is down, and x402 settlement still runs when the handler returns success.

---

Ship the loop. Identify the agent. Sign on Base when the toll comes due. Keep the same idempotency key when you retry.
