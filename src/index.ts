import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { Context, MiddlewareHandler } from 'hono';
import { getAddress } from 'viem';
import { exact } from 'x402/schemes';
import {
  findMatchingPaymentRequirements,
  processPriceToAtomicAmount,
  toJsonSafe,
} from 'x402/shared';
import {
  SupportedEVMNetworks,
  settleResponseHeader,
  type Network,
  type PaymentRequirements,
  type Resource,
} from 'x402/types';
import { useFacilitator } from 'x402/verify';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DEFAULT_FREE_TIER_LIMIT = 100;
const DEFAULT_TELEMETRY_PRICE = '$0.001';
const DEFAULT_X402_NETWORK: Network = 'base';
const DEFAULT_FACILITATOR_URL = 'https://x402.org/facilitator';
const X402_VERSION = 1;
const LOW_BALANCE_THRESHOLD = 10;
const ALERT_COOLDOWN_MS = 4 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Env {
  ASSETS: Fetcher;
  USAGE_KV: KVNamespace;
  X402_PAY_TO: string;
  ADMIN_SECRET?: string;
  FREE_TIER_LIMIT?: string;
  TELEMETRY_PRICE?: string;
  X402_NETWORK?: string;
  X402_FACILITATOR_URL?: string;
  SUPABASE_URL?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
  ALERT_WEBHOOK_URL?: string;
}

type BillingMode = 'free' | 'paid';

type Variables = {
  agentId: string;
  billingMode: BillingMode;
  usageCount: number;
  freeTierLimit: number;
  telemetryBody?: TelemetryBlip;
  idempotencyKey?: string;
};

type TelemetryBlip = {
  event: string;
  payload?: Record<string, unknown>;
  sessionId?: string;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  agentId?: string;
  agent_id?: string;
};

type UsageRecord = {
  count: number;
  lastEvent?: string;
  lastSeen?: string;
  billingMode?: BillingMode;
  freeTierLimit?: number;
  blocked?: boolean;
};

type AdminAction = 'reset' | 'set_limit' | 'block' | 'unblock';

type AdminAgentBody = {
  action?: AdminAction;
  resetUsage?: boolean;
  freeTierLimit?: number | string;
  blocked?: boolean;
};

type ActivityEntry = {
  blipId: string;
  agentId: string;
  event: string;
  billingMode: BillingMode;
  ingestedAt: string;
};

const ACTIVITY_KEY = 'activity:recent';
const ACTIVITY_LIMIT = 40;
const ACTIVE_WINDOW_MS = 5 * 60 * 1000;
const IDEMPOTENCY_TTL_SECONDS = 60;
const IDEMPOTENCY_HEADER_MAX = 200;

type IdempotencyCache = {
  status: number;
  body: unknown;
  paymentResponse?: string;
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resolveAgentId(c: Context<{ Bindings: Env; Variables: Variables }>): string | null {
  const headerId = c.req.header('X-Agent-Id')?.trim();
  if (headerId) return headerId;
  return null;
}

function usageKey(agentId: string): string {
  return `usage:${agentId}`;
}

function parseUsageRecord(raw: string | null): UsageRecord {
  if (!raw) return { count: 0 };
  const asInt = Number.parseInt(raw, 10);
  if (raw === String(asInt) && Number.isFinite(asInt) && asInt >= 0) {
    return { count: asInt };
  }
  try {
    const parsed = JSON.parse(raw) as UsageRecord;
    const count = Number(parsed.count);
    const limit = Number(parsed.freeTierLimit);
    return {
      count: Number.isFinite(count) && count >= 0 ? count : 0,
      lastEvent: typeof parsed.lastEvent === 'string' ? parsed.lastEvent : undefined,
      lastSeen: typeof parsed.lastSeen === 'string' ? parsed.lastSeen : undefined,
      billingMode: parsed.billingMode === 'paid' ? 'paid' : parsed.billingMode === 'free' ? 'free' : undefined,
      freeTierLimit: Number.isFinite(limit) && limit > 0 ? limit : undefined,
      blocked: parsed.blocked === true,
    };
  } catch {
    return { count: 0 };
  }
}

async function getUsageRecord(kv: KVNamespace, agentId: string): Promise<UsageRecord> {
  return parseUsageRecord(await kv.get(usageKey(agentId)));
}

function defaultFreeTierLimit(env: Env): number {
  return parsePositiveInt(env.FREE_TIER_LIMIT, DEFAULT_FREE_TIER_LIMIT);
}

function resolveAgentFreeTierLimit(record: UsageRecord, env: Env): number {
  return record.freeTierLimit && record.freeTierLimit > 0
    ? record.freeTierLimit
    : defaultFreeTierLimit(env);
}

async function secretsMatch(provided: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(provided)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function resolveAdminSecret(c: Context<{ Bindings: Env }>): string | null {
  const headerKey = c.req.header('X-Admin-Key')?.trim();
  if (headerKey) return headerKey;
  const authorization = c.req.header('Authorization')?.trim();
  if (authorization?.toLowerCase().startsWith('bearer ')) {
    return authorization.slice(7).trim();
  }
  return null;
}

async function getUsageCount(kv: KVNamespace, agentId: string): Promise<number> {
  const record = await getUsageRecord(kv, agentId);
  return record.count;
}

async function putUsageRecord(kv: KVNamespace, agentId: string, record: UsageRecord): Promise<void> {
  await kv.put(usageKey(agentId), JSON.stringify(record));
}

async function incrementUsageCount(kv: KVNamespace, agentId: string): Promise<number> {
  const current = await getUsageRecord(kv, agentId);
  const next = current.count + 1;
  await putUsageRecord(kv, agentId, {
    ...current,
    count: next,
    lastSeen: new Date().toISOString(),
    billingMode: 'free',
  });
  return next;
}

async function touchUsageRecord(
  kv: KVNamespace,
  agentId: string,
  patch: Pick<UsageRecord, 'lastEvent' | 'billingMode'>,
): Promise<void> {
  const current = await getUsageRecord(kv, agentId);
  await putUsageRecord(kv, agentId, {
    ...current,
    lastEvent: patch.lastEvent ?? current.lastEvent,
    billingMode: patch.billingMode ?? current.billingMode,
    lastSeen: new Date().toISOString(),
  });
}

function serializeAgentSnapshot(agentId: string, record: UsageRecord, env: Env) {
  const freeTierLimit = resolveAgentFreeTierLimit(record, env);
  const usageCount = record.count;
  return {
    agentId,
    usageCount,
    freeTierLimit,
    remainingFreeBlips: Math.max(freeTierLimit - usageCount, 0),
    blocked: record.blocked === true,
    paymentRequired: !record.blocked && usageCount >= freeTierLimit,
    billingMode: record.billingMode ?? null,
    lastEvent: record.lastEvent ?? null,
    lastSeen: record.lastSeen ?? null,
  };
}

function lastAlertKey(agentId: string): string {
  return `last-alert:${agentId}`;
}

async function maybeSendLowBalanceAlert(params: {
  env: Env;
  agentId: string;
  usageCount: number;
  freeTierLimit: number;
  remainingFreeBlips: number;
  billingMode: BillingMode;
}): Promise<void> {
  const { env, agentId, usageCount, freeTierLimit, remainingFreeBlips, billingMode } = params;
  if (remainingFreeBlips > LOW_BALANCE_THRESHOLD) {
    return;
  }

  const webhookUrl = env.ALERT_WEBHOOK_URL?.trim();
  if (!webhookUrl) {
    return;
  }

  try {
    const previous = await env.USAGE_KV.get(lastAlertKey(agentId));
    if (previous) {
      const lastAlertAt = Date.parse(previous);
      if (Number.isFinite(lastAlertAt) && Date.now() - lastAlertAt < ALERT_COOLDOWN_MS) {
        return;
      }
    }

    const alertedAt = new Date().toISOString();
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'low_balance',
        agentId,
        usageCount,
        freeTierLimit,
        remainingFreeBlips,
        threshold: LOW_BALANCE_THRESHOLD,
        billingMode,
        pricePerBlip: env.TELEMETRY_PRICE ?? DEFAULT_TELEMETRY_PRICE,
        network: env.X402_NETWORK ?? DEFAULT_X402_NETWORK,
        message:
          remainingFreeBlips === 0
            ? `Agent ${agentId} has exhausted its free-tier blips and may require x402 settlement.`
            : `Agent ${agentId} is low on free-tier blips (${remainingFreeBlips} remaining).`,
        alertedAt,
      }),
    });

    if (!response.ok) {
      console.error('[alert] webhook failed:', response.status);
      return;
    }

    await env.USAGE_KV.put(lastAlertKey(agentId), alertedAt, {
      expirationTtl: Math.ceil(ALERT_COOLDOWN_MS / 1000),
    });
  } catch (error) {
    console.error('[alert] low-balance notification failed:', error);
  }
}

async function appendActivity(kv: KVNamespace, entry: ActivityEntry): Promise<void> {
  const raw = await kv.get(ACTIVITY_KEY);
  let recent: ActivityEntry[] = [];
  if (raw) {
    try {
      recent = JSON.parse(raw) as ActivityEntry[];
      if (!Array.isArray(recent)) recent = [];
    } catch {
      recent = [];
    }
  }
  recent.unshift(entry);
  await kv.put(ACTIVITY_KEY, JSON.stringify(recent.slice(0, ACTIVITY_LIMIT)));
}

async function listAgentUsage(kv: KVNamespace): Promise<Array<{ agentId: string; record: UsageRecord }>> {
  const agents: Array<{ agentId: string; record: UsageRecord }> = [];
  let cursor: string | undefined;

  do {
    const page = await kv.list({ prefix: 'usage:', cursor });
    const records = await Promise.all(
      page.keys.map(async (key) => {
        const agentId = key.name.slice('usage:'.length);
        return { agentId, record: parseUsageRecord(await kv.get(key.name)) };
      }),
    );
    agents.push(...records);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return agents;
}

function resolveResourceUrl(c: Context): string {
  const forwardedProto = c.req.header('X-Forwarded-Proto');
  const forwardedHost = c.req.header('X-Forwarded-Host');
  if (forwardedProto && forwardedHost) {
    const url = new URL(c.req.url);
    return `${forwardedProto}://${forwardedHost}${url.pathname}${url.search}`;
  }
  return c.req.url;
}

function buildPaymentRequirements(
  c: Context<{ Bindings: Env }>,
  payTo: `0x${string}`,
  network: Network,
  price: string,
): PaymentRequirements[] | { error: string } {
  const atomicAmount = processPriceToAtomicAmount(price, network);
  if ('error' in atomicAmount) {
    return { error: atomicAmount.error };
  }

  const { maxAmountRequired, asset } = atomicAmount;
  const method = c.req.method.toUpperCase();
  const resourceUrl = resolveResourceUrl(c);

  if (!SupportedEVMNetworks.includes(network)) {
    return { error: `Unsupported x402 network: ${network}` };
  }

  return [
    {
      scheme: 'exact',
      network,
      maxAmountRequired,
      resource: resourceUrl as Resource,
      description: 'Agentblips telemetry blip ingestion',
      mimeType: 'application/json',
      payTo: getAddress(payTo),
      maxTimeoutSeconds: 300,
      asset: getAddress(asset.address),
      outputSchema: {
        input: {
          type: 'http',
          method,
          discoverable: true,
        },
        output: {
          type: 'object',
          properties: {
            status: { type: 'string' },
            blipId: { type: 'string' },
            billingMode: { type: 'string' },
          },
        },
      },
      extra: asset.eip712,
    },
  ];
}

async function persistTelemetryBlip(
  env: Env,
  agentId: string,
  blip: TelemetryBlip,
  billingMode: BillingMode,
): Promise<{ blipId: string; persisted: boolean }> {
  const blipId = crypto.randomUUID();
  const record = {
    id: blipId,
    agent_id: agentId,
    event: blip.event,
    payload: blip.payload ?? {},
    session_id: blip.sessionId ?? null,
    metadata: blip.metadata ?? {},
    billing_mode: billingMode,
    client_timestamp: blip.timestamp ?? null,
    ingested_at: new Date().toISOString(),
  };

  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.log('[telemetry:local]', JSON.stringify(record));
    return { blipId, persisted: false };
  }

  const response = await fetch(`${env.SUPABASE_URL}/rest/v1/telemetry_blips`, {
    method: 'POST',
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
      'Content-Type': 'application/json',
      Prefer: 'return=minimal',
    },
    body: JSON.stringify(record),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Supabase ingest failed (${response.status}): ${detail}`);
  }

  return { blipId, persisted: true };
}

function idempotencyKvKey(agentId: string, key: string): string {
  return `idem:${agentId}:${key}`;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function resolveIdempotencyKey(
  agentId: string,
  headerValue: string | undefined,
  rawBody: string,
  timestamp: string | undefined,
): Promise<string> {
  const provided = headerValue?.trim();
  if (provided) {
    return provided.length > IDEMPOTENCY_HEADER_MAX ? sha256Hex(provided) : provided;
  }
  return sha256Hex(`${agentId}\n${timestamp ?? ''}\n${rawBody}`);
}

function replayIdempotentResponse(cache: IdempotencyCache): Response {
  const body =
    cache.body && typeof cache.body === 'object'
      ? { ...(cache.body as Record<string, unknown>), idempotentReplay: true }
      : cache.body;
  const response = new Response(JSON.stringify(body), {
    status: cache.status,
    headers: {
      'Content-Type': 'application/json',
      'X-Idempotency-Replayed': 'true',
    },
  });
  if (cache.paymentResponse) {
    response.headers.set('X-PAYMENT-RESPONSE', cache.paymentResponse);
  }
  return response;
}

function createTelemetryIdempotencyGate(): MiddlewareHandler<{
  Bindings: Env;
  Variables: Variables;
}> {
  return async (c, next) => {
    const agentId = resolveAgentId(c);
    if (!agentId) {
      return next();
    }

    let rawBody: string;
    try {
      rawBody = await c.req.text();
    } catch {
      return next();
    }

    let body: TelemetryBlip;
    try {
      body = JSON.parse(rawBody) as TelemetryBlip;
    } catch {
      return c.json(
        {
          status: 'error',
          code: 'INVALID_JSON',
          message: 'Request body must be valid JSON.',
        },
        400,
      );
    }

    c.set('telemetryBody', body);

    const timestamp = typeof body.timestamp === 'string' ? body.timestamp : undefined;
    const idempotencyKey = await resolveIdempotencyKey(
      agentId,
      c.req.header('X-Idempotency-Key'),
      rawBody,
      timestamp,
    );
    c.set('idempotencyKey', idempotencyKey);

    const cache = await c.env.USAGE_KV.get<IdempotencyCache>(
      idempotencyKvKey(agentId, idempotencyKey),
      'json',
    );
    if (cache && typeof cache.status === 'number' && cache.status < 400) {
      return replayIdempotentResponse(cache);
    }

    await next();

    const response = c.res;
    if (!response || response.status >= 400) {
      return;
    }

    try {
      const payload = await response.clone().json();
      const record: IdempotencyCache = {
        status: response.status,
        body: payload,
        paymentResponse: response.headers.get('X-PAYMENT-RESPONSE') ?? undefined,
      };
      await c.env.USAGE_KV.put(idempotencyKvKey(agentId, idempotencyKey), JSON.stringify(record), {
        expirationTtl: IDEMPOTENCY_TTL_SECONDS,
      });
    } catch (error) {
      console.error('[idempotency] failed to cache response:', error);
    }
  };
}

// ---------------------------------------------------------------------------
// Middleware: free tier + x402 payment gate
// ---------------------------------------------------------------------------

function createTelemetryPaymentGate(): MiddlewareHandler<{
  Bindings: Env;
  Variables: Variables;
}> {
  return async (c, next) => {
    const agentId = resolveAgentId(c);
    if (!agentId) {
      return c.json(
        {
          status: 'error',
          code: 'AGENT_ID_REQUIRED',
          message: 'Provide a stable agent identifier via the X-Agent-Id header.',
        },
        401,
      );
    }

    const record = await getUsageRecord(c.env.USAGE_KV, agentId);
    if (record.blocked) {
      return c.json(
        {
          status: 'error',
          code: 'AGENT_BLOCKED',
          message: 'This agent has been blocked by an administrator.',
          agentId,
        },
        403,
      );
    }

    const freeTierLimit = resolveAgentFreeTierLimit(record, c.env);
    const usageCount = record.count;

    c.set('agentId', agentId);
    c.set('freeTierLimit', freeTierLimit);
    c.set('usageCount', usageCount);

    // Free allowance still available — increment and bypass x402.
    if (usageCount < freeTierLimit) {
      const updatedCount = await incrementUsageCount(c.env.USAGE_KV, agentId);
      c.set('usageCount', updatedCount);
      c.set('billingMode', 'free');
      return next();
    }

    // Allowance exhausted — enforce x402 micro-settlement.
    c.set('billingMode', 'paid');

    const payTo = c.env.X402_PAY_TO as `0x${string}` | undefined;
    if (!payTo) {
      return c.json(
        {
          status: 'error',
          code: 'PAYMENT_CONFIG_MISSING',
          message: 'X402_PAY_TO secret is not configured on the worker.',
        },
        500,
      );
    }

    const network = (c.env.X402_NETWORK ?? DEFAULT_X402_NETWORK) as Network;
    const price = c.env.TELEMETRY_PRICE ?? DEFAULT_TELEMETRY_PRICE;
    const facilitatorUrl = (c.env.X402_FACILITATOR_URL ?? DEFAULT_FACILITATOR_URL) as Resource;

    const requirementsResult = buildPaymentRequirements(c, payTo, network, price);
    if ('error' in requirementsResult) {
      return c.json(
        {
          status: 'error',
          code: 'PAYMENT_CONFIG_INVALID',
          message: requirementsResult.error,
        },
        500,
      );
    }

    const paymentRequirements = requirementsResult;
    const paymentHeader = c.req.header('X-PAYMENT');

    if (!paymentHeader) {
      return c.json(
        {
          status: 'payment_required',
          code: 'FREE_TIER_EXHAUSTED',
          message: `Free telemetry allowance exhausted (${freeTierLimit} blips). Retry with an X-PAYMENT header to settle ${price} USDC on ${network}.`,
          agentId,
          usageCount,
          freeTierLimit,
          x402Version: X402_VERSION,
          accepts: paymentRequirements,
        },
        402,
      );
    }

    let decodedPayment;
    try {
      decodedPayment = exact.evm.decodePayment(paymentHeader);
      decodedPayment.x402Version = X402_VERSION;
    } catch (error) {
      return c.json(
        {
          status: 'payment_required',
          code: 'INVALID_PAYMENT',
          message: error instanceof Error ? error.message : 'Invalid or malformed X-PAYMENT header',
          x402Version: X402_VERSION,
          accepts: paymentRequirements,
        },
        402,
      );
    }

    const selectedRequirements = findMatchingPaymentRequirements(
      paymentRequirements,
      decodedPayment,
    );

    if (!selectedRequirements) {
      return c.json(
        {
          status: 'payment_required',
          code: 'NO_MATCHING_REQUIREMENTS',
          message: 'Unable to find matching payment requirements for the supplied X-PAYMENT header.',
          x402Version: X402_VERSION,
          accepts: toJsonSafe(paymentRequirements),
        },
        402,
      );
    }

    const { verify, settle } = useFacilitator({ url: facilitatorUrl });

    try {
      const verification = await verify(decodedPayment, selectedRequirements);
      if (!verification.isValid) {
        return c.json(
          {
            status: 'payment_required',
            code: 'VERIFICATION_FAILED',
            message: verification.invalidReason ?? 'Payment verification failed',
            payer: verification.payer,
            x402Version: X402_VERSION,
            accepts: paymentRequirements,
          },
          402,
        );
      }
    } catch (error) {
      console.error('[x402] verification error:', error);
      return c.json(
        {
          status: 'payment_required',
          code: 'VERIFICATION_ERROR',
          message: error instanceof Error ? error.message : 'Payment verification failed',
          x402Version: X402_VERSION,
          accepts: paymentRequirements,
        },
        402,
      );
    }

    await next();

    const response = c.res;
    if (!response || response.status >= 400) {
      return;
    }

    c.res = undefined;

    try {
      const settlement = await settle(decodedPayment, selectedRequirements);
      if (!settlement.success) {
        throw new Error(settlement.errorReason ?? 'Settlement failed');
      }

      response.headers.set('X-PAYMENT-RESPONSE', settleResponseHeader(settlement));
      c.res = response;
    } catch (error) {
      c.res = c.json(
        {
          status: 'payment_required',
          code: 'SETTLEMENT_FAILED',
          message: error instanceof Error ? error.message : 'Failed to settle payment on-chain',
          x402Version: X402_VERSION,
          accepts: paymentRequirements,
        },
        402,
      );
    }
  };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

app.use(
  '*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'X-Agent-Id', 'X-PAYMENT', 'X-Admin-Key', 'Authorization', 'X-Idempotency-Key'],
    exposeHeaders: ['X-PAYMENT-RESPONSE', 'X-Idempotency-Replayed'],
  }),
);

app.get('/api', (c) => {
  return c.json({
    project: 'AgentBlips',
    status: 'online',
    message: 'Real-time telemetry HUD and monitoring sink for autonomous AI agent loops.',
    protocol: 'x402',
    endpoints: {
      telemetry: 'POST /api/telemetry',
      telemetryStatus: 'GET /api/telemetry/status',
      telemetryOverview: 'GET /api/telemetry/overview',
      adminAgent: 'POST /api/admin/agent',
    },
  });
});

app.get('/api/telemetry/overview', async (c) => {
  const freeTierLimit = parsePositiveInt(c.env.FREE_TIER_LIMIT, DEFAULT_FREE_TIER_LIMIT);
  const pricePerBlip = c.env.TELEMETRY_PRICE ?? DEFAULT_TELEMETRY_PRICE;
  const network = c.env.X402_NETWORK ?? DEFAULT_X402_NETWORK;
  const now = Date.now();

  const listed = await listAgentUsage(c.env.USAGE_KV);
  const agents = listed.map(({ agentId, record }) => {
    const usageCount = record.count;
    const freeTierLimitForAgent = resolveAgentFreeTierLimit(record, c.env);
    const remainingFreeBlips = Math.max(freeTierLimitForAgent - usageCount, 0);
    const lastSeenMs = record.lastSeen ? Date.parse(record.lastSeen) : NaN;
    const active = Number.isFinite(lastSeenMs) && now - lastSeenMs < ACTIVE_WINDOW_MS;
    const paymentRequired = !record.blocked && usageCount >= freeTierLimitForAgent;

    return {
      agentId,
      usageCount,
      freeTierLimit: freeTierLimitForAgent,
      remainingFreeBlips,
      paymentRequired,
      blocked: record.blocked === true,
      settlementStatus: record.blocked
        ? 'blocked'
        : paymentRequired
          ? 'x402_required'
          : 'free_tier',
      billingMode: record.billingMode ?? (paymentRequired ? 'paid' : 'free'),
      lastEvent: record.lastEvent ?? null,
      lastSeen: record.lastSeen ?? null,
      active,
    };
  });

  agents.sort((a, b) => {
    if (a.active !== b.active) return a.active ? -1 : 1;
    return (b.lastSeen ?? '').localeCompare(a.lastSeen ?? '');
  });

  const activityRaw = await c.env.USAGE_KV.get(ACTIVITY_KEY);
  let recent: ActivityEntry[] = [];
  if (activityRaw) {
    try {
      const parsed = JSON.parse(activityRaw) as ActivityEntry[];
      if (Array.isArray(parsed)) recent = parsed;
    } catch {
      recent = [];
    }
  }

  const activeAgents = agents.filter((agent) => agent.active).length;
  const usageCount = agents.reduce((sum, agent) => sum + agent.usageCount, 0);
  const remainingFreeBlips = agents
    .filter((agent) => !agent.blocked)
    .reduce((sum, agent) => sum + agent.remainingFreeBlips, 0);
  const paidAgents = agents.filter((agent) => agent.paymentRequired).length;
  const blockedAgents = agents.filter((agent) => agent.blocked).length;

  return c.json({
    status: 'success',
    worker: 'online',
    protocol: 'x402',
    network,
    pricePerBlip,
    freeTierLimit,
    totals: {
      agents: agents.length,
      activeAgents,
      usageCount,
      remainingFreeBlips,
      paidAgents,
      blockedAgents,
      settlementStatus: paidAgents > 0 ? 'x402_required' : 'free_tier',
    },
    agents,
    recent,
  });
});

app.get('/api/telemetry/status', async (c) => {
  const agentId = resolveAgentId(c);
  if (!agentId) {
    return c.json(
      {
        status: 'error',
        code: 'AGENT_ID_REQUIRED',
        message: 'Provide a stable agent identifier via the X-Agent-Id header.',
      },
      401,
    );
  }

  const record = await getUsageRecord(c.env.USAGE_KV, agentId);
  const freeTierLimit = resolveAgentFreeTierLimit(record, c.env);
  const usageCount = record.count;
  const remaining = Math.max(freeTierLimit - usageCount, 0);

  return c.json({
    status: 'success',
    agentId,
    usageCount,
    freeTierLimit,
    remainingFreeBlips: remaining,
    paymentRequired: !record.blocked && usageCount >= freeTierLimit,
    blocked: record.blocked === true,
    pricePerBlip: c.env.TELEMETRY_PRICE ?? DEFAULT_TELEMETRY_PRICE,
    network: c.env.X402_NETWORK ?? DEFAULT_X402_NETWORK,
  });
});

app.post('/api/telemetry', createTelemetryIdempotencyGate(), createTelemetryPaymentGate(), async (c) => {
  const body = c.get('telemetryBody');
  if (!body) {
    return c.json(
      {
        status: 'error',
        code: 'INVALID_JSON',
        message: 'Request body must be valid JSON.',
      },
      400,
    );
  }

  if (!body.event || typeof body.event !== 'string') {
    return c.json(
      {
        status: 'error',
        code: 'INVALID_EVENT',
        message: 'Telemetry payload must include a string "event" field.',
      },
      400,
    );
  }

  const agentId = c.get('agentId');
  const billingMode = c.get('billingMode');

  try {
    const { blipId, persisted } = await persistTelemetryBlip(c.env, agentId, body, billingMode);

    await touchUsageRecord(c.env.USAGE_KV, agentId, {
      lastEvent: body.event,
      billingMode,
    });
    await appendActivity(c.env.USAGE_KV, {
      blipId,
      agentId,
      event: body.event,
      billingMode,
      ingestedAt: new Date().toISOString(),
    });

    const usageCount = c.get('usageCount');
    const freeTierLimit = c.get('freeTierLimit');
    const remainingFreeBlips = Math.max(freeTierLimit - usageCount, 0);

    c.executionCtx.waitUntil(
      maybeSendLowBalanceAlert({
        env: c.env,
        agentId,
        usageCount,
        freeTierLimit,
        remainingFreeBlips,
        billingMode,
      }),
    );

    return c.json({
      status: 'success',
      blipId,
      agentId,
      event: body.event,
      billingMode,
      persisted,
      usageCount,
      freeTierLimit,
      ingestedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error('[telemetry] ingest error:', error);
    return c.json(
      {
        status: 'error',
        code: 'INGEST_FAILED',
        message: error instanceof Error ? error.message : 'Failed to persist telemetry blip',
      },
      500,
    );
  }
});

app.post('/api/admin/agent', async (c) => {
  const expected = c.env.ADMIN_SECRET?.trim();
  if (!expected) {
    return c.json(
      {
        status: 'error',
        code: 'ADMIN_SECRET_MISSING',
        message: 'ADMIN_SECRET is not configured on the worker.',
      },
      503,
    );
  }

  const provided = resolveAdminSecret(c);
  if (!provided || !(await secretsMatch(provided, expected))) {
    return c.json(
      {
        status: 'error',
        code: 'ADMIN_UNAUTHORIZED',
        message: 'Provide a valid admin credential via the X-Admin-Key header.',
      },
      401,
    );
  }

  const agentId = resolveAgentId(c);
  if (!agentId) {
    return c.json(
      {
        status: 'error',
        code: 'AGENT_ID_REQUIRED',
        message: 'Provide a stable agent identifier via the X-Agent-Id header.',
      },
      400,
    );
  }

  let body: AdminAgentBody = {};
  const contentType = c.req.header('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    try {
      body = await c.req.json<AdminAgentBody>();
    } catch {
      return c.json(
        {
          status: 'error',
          code: 'INVALID_JSON',
          message: 'Request body must be valid JSON.',
        },
        400,
      );
    }
  }

  const record = await getUsageRecord(c.env.USAGE_KV, agentId);
  const applied: string[] = [];

  if (body.action === 'reset' || body.resetUsage === true) {
    record.count = 0;
    record.billingMode = 'free';
    applied.push('resetUsage');
  }

  if (body.action === 'block' || body.blocked === true) {
    record.blocked = true;
    applied.push('block');
  }

  if (body.action === 'unblock' || body.blocked === false) {
    record.blocked = false;
    applied.push('unblock');
  }

  const shouldSetLimit = body.action === 'set_limit' || body.freeTierLimit !== undefined;
  if (shouldSetLimit) {
    const nextLimit = parsePositiveInt(
      typeof body.freeTierLimit === 'number' ? String(body.freeTierLimit) : body.freeTierLimit,
      0,
    );
    if (nextLimit <= 0) {
      return c.json(
        {
          status: 'error',
          code: 'INVALID_LIMIT',
          message: 'freeTierLimit must be a positive integer.',
        },
        400,
      );
    }
    record.freeTierLimit = nextLimit;
    applied.push('setLimit');
  }

  if (applied.length === 0) {
    return c.json(
      {
        status: 'error',
        code: 'NO_ADMIN_ACTION',
        message: 'Specify action: reset, set_limit, block, or unblock.',
      },
      400,
    );
  }

  await putUsageRecord(c.env.USAGE_KV, agentId, record);

  return c.json({
    status: 'success',
    applied,
    agent: serializeAgentSnapshot(agentId, record, c.env),
  });
});

export default app;
