# Tollbase Core ⚡️

> Drop-in edge telemetry and automated x402 monetization for autonomous AI agents. Built on Cloudflare Workers and Base.

Tollbase provides a frictionless cryptographic toll booth for autonomous agents. When an agent exhausts its free tier, our edge worker responds with an HTTP `402 Payment Required` challenge. The client SDK automatically signs an EIP-3009 micro-settlement in USDC on Base, settles instantly, and continues its execution loop without human intervention.

The same origin serves a **live telemetry HUD**—deep navy, charcoal, parchment, tarnished gold, and red—so operators can watch the loop without a second app.

---

## Live telemetry HUD

Open the Worker origin. The dashboard is the product surface, not an afterthought.

**[tollbase.com](https://tollbase.com)**

It polls `/api/telemetry/overview` and `/api/telemetry/activity` every few seconds. No SDK, no extra auth for read-only fleet view.

| Capability | What you see |
| --- | --- |
| **Live activity polling** | Successful events stream in as they ingest—event name, agent, time |
| **Copyable blip IDs** | Each row exposes the ingest UUID; copy is one click |
| **Basescan transaction hashes** | Paid x402 settlements link the hash to Basescan on Base; free-tier blips stay marked off-chain |
| **Fleet meters** | Active agents, usage, remaining free-tier, x402 posture, block state |

Paid rows use red. Identifiers sit in gold on charcoal panels over navy. Body copy is parchment.

---

## 🚀 Quickstart in 60 Seconds

### 1. Install Dependencies

```bash
npm install tollbase-core viem x402
```

### 2. Initialize the Client

```ts
import { TollbaseClient } from 'tollbase-core';

const client = new TollbaseClient({
  endpoint: 'https://tollbase.com',
  agentId: 'my-ai-agent-001',
  privateKey: process.env.AGENT_PRIVATE_KEY as `0x${string}`, // Base wallet with USDC
});

// Send telemetry (auto-manages free tier & 402 payments)
await client.sendTelemetry('heartbeat', { status: 'operational' });
```

The first 100 blips per agent are free. After that, the SDK retries with a signed `X-PAYMENT` header. Pass an `idempotencyKey` on retries so usage and settlement are not applied twice:

```ts
await client.sendTelemetry(
  'heartbeat',
  { status: 'operational' },
  { idempotencyKey: 'run-42-step-1' },
);
```

Blips appear on the HUD on the next poll. Paid settlements show a Basescan link once the facilitator returns a transaction hash.

Full operator guide: [QUICKSTART.md](./QUICKSTART.md) · protocol internals: [WIKI.md](./WIKI.md)
