# Agentblips Quickstart

Real-time telemetry for autonomous agent loops. Free-tier ingest first. When the allowance is gone, **x402** settles **USDC on Base** and the loop keeps running.

Endpoint: `https://agentblips-core.agentblips-spenser.workers.dev`

---

## 1. Install the client

The TypeScript SDK lives in this repository as `src/client.ts`. Add the package (or clone the repo) and install the signing stack it depends on:

```bash
npm install agentblips-core
# or, from a local checkout:
# npm install ./agentblips-core

npm install viem x402
```

Import the client:

```ts
import { AgentBlipsClient } from 'agentblips-core/src/client';
```

If you are working inside this repo:

```ts
import { AgentBlipsClient } from './src/client';
```

Node 18+ (global `fetch`) or a Cloudflare Worker / modern browser runtime is required.

---

## 2. Initialize `AgentBlipsClient`

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

Without a signer, free-tier blips still ingest. Once the allowance is exhausted, `sendTelemetry()` returns a 402 challenge instead of settling automatically.

**Wallet requirements**

- Fund the address with **USDC on Base** (not ETH-only).
- Keep the key in an environment variable. Never commit it.
- Default price is **$0.001 USDC per blip** after the free tier.

Check remaining allowance before you loop:

```ts
const status = await client.getStatus();
// usageCount, freeTierLimit, remainingFreeBlips, paymentRequired, pricePerBlip, network
```

---

## 3. Send telemetry blips

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

## 4. Allowances and 402 challenges

### Default free tier

Each agent gets **100 blips** (configurable per worker via `FREE_TIER_LIMIT`). After that, ingest requires x402.

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
| `POST` | `/api/telemetry` | Ingest (`X-Agent-Id`, optional `X-PAYMENT`, `X-Idempotency-Key`) |
| `GET` | `/api/telemetry/overview` | Fleet metrics |
| `POST` | `/api/admin/agent` | Fleet admin (`X-Admin-Key` + `X-Agent-Id`) |

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

---

Ship the loop. Identify the agent. Sign on Base when the toll comes due. Keep the same idempotency key when you retry.
