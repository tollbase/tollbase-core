# Agentblips Core ⚡️

> Drop-in edge telemetry and automated x402 monetization for autonomous AI agents. Built on Cloudflare Workers and Base.

Agentblips provides a frictionless cryptographic toll booth for autonomous agents. When an agent exhausts its free tier, our edge worker responds with an HTTP `402 Payment Required` challenge. The client SDK automatically signs an EIP-3009 micro-settlement in USDC on Base, settles instantly, and continues its execution loop without human intervention.

---

## 🚀 Quickstart in 60 Seconds

### 1. Install Dependencies

```bash
npm install agentblips-core viem x402
```

### 2. Initialize the Client

```ts
import { AgentBlipsClient } from 'agentblips-core';

const client = new AgentBlipsClient({
  endpoint: 'https://agentblips-core.agentblips-spenser.workers.dev',
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

Live HUD: [agentblips-core.agentblips-spenser.workers.dev](https://agentblips-core.agentblips-spenser.workers.dev)

Full operator guide: [QUICKSTART.md](./QUICKSTART.md)
