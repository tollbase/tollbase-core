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
const DEFAULT_PLATFORM_FREE_LIMIT = 5000;
const DEFAULT_OWNER_ID = 'default';
const DEFAULT_TELEMETRY_PRICE = '$0.001';
const DEFAULT_X402_NETWORK: Network = 'base';
const DEFAULT_FACILITATOR_URL = 'https://x402.org/facilitator';
const X402_VERSION = 1;
const LOW_BALANCE_THRESHOLD = 10;
const ALERT_COOLDOWN_MS = 4 * 60 * 60 * 1000;
const KV_TIMEOUT_MS = 800;
const KV_LIST_TIMEOUT_MS = 2000;
const SUPABASE_TIMEOUT_MS = 1500;
const MAX_TELEMETRY_BODY_BYTES = 32 * 1024;
const MAX_PAYMENT_HEADER_BYTES = 8 * 1024;
const MAX_EVENT_CHARS = 200;
const PAYMENT_VALID_BEFORE_SKEW_SECONDS = 6;
const PAYMENT_MAX_FUTURE_SECONDS = 3600;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const DEFAULT_RATE_LIMIT_PER_AGENT = 120;
const DEFAULT_RATE_LIMIT_PER_IP = 240;
const PAYMENT_HEADER_CHARSET = /^[A-Za-z0-9+/_=-]+$/;
const EIP3009_NONCE_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const EVM_SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130,1024}$/;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Env {
  ASSETS: Fetcher;
  USAGE_KV: KVNamespace;
  X402_PAY_TO: string;
  ADMIN_SECRET?: string;
  OWNER_ID?: string;
  PLATFORM_FREE_LIMIT?: string;
  SUBSCRIPTION_ACTIVE?: string;
  FREE_TIER_LIMIT?: string;
  TELEMETRY_PRICE?: string;
  X402_NETWORK?: string;
  X402_FACILITATOR_URL?: string;
  SUPABASE_URL?: string;
  SUPABASE_SERVICE_ROLE_KEY?: string;
  ALERT_WEBHOOK_URL?: string;
  RATE_LIMIT_PER_AGENT?: string;
  RATE_LIMIT_PER_IP?: string;
}

type BillingMode = 'free' | 'paid';

type Variables = {
  agentId: string;
  billingMode: BillingMode;
  usageCount: number;
  freeTierLimit: number;
  telemetryBody?: TelemetryBlip;
  idempotencyKey?: string;
  blipId?: string;
  radar?: RadarForensics;
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
type OwnerAdminAction = 'subscribe' | 'unsubscribe' | 'reset_tracked';

type AdminAgentBody = {
  action?: AdminAction;
  resetUsage?: boolean;
  freeTierLimit?: number | string;
  blocked?: boolean;
};

type AdminOwnerBody = {
  action?: OwnerAdminAction;
  subscriptionActive?: boolean;
  resetTracked?: boolean;
};

type OwnerRecord = {
  ownerId: string;
  trackedBlips: number;
  subscriptionActive?: boolean;
  lastSeen?: string;
};

type DirectoryNode = {
  nodeId: string;
  siteName: string;
  domain: string;
  origin: string;
  description?: string;
  active: boolean;
  optedIn: boolean;
  network: string;
  currency: string;
  pricePerBlip: string;
  x402Version: number;
  scheme: 'exact';
  facilitatorUrl: string;
  ingestUrl: string;
  statusUrl: string;
  directoryUrl: string;
  ownerId?: string;
  registeredAt: string;
  updatedAt: string;
  lastSeen?: string;
};

type DirectoryAdminAction = 'register' | 'update' | 'activate' | 'deactivate';

type DirectoryAdminBody = {
  action?: DirectoryAdminAction;
  domain?: string;
  siteName?: string;
  description?: string;
  ingestPath?: string;
  active?: boolean;
};

type BotSignature = {
  labels: string[];
  verifiedBot?: boolean;
  score?: number;
  detectionIds?: number[];
};

type RadarForensics = {
  method: string;
  path: string;
  timestamp: string;
  sourceIp: string;
  userAgent: string;
  bot: BotSignature;
  headers: Record<string, string>;
  authenticated: boolean;
  country?: string;
  asOrganization?: string;
  ray?: string;
};

type ActivityEntry = {
  blipId: string;
  agentId: string;
  event: string;
  billingMode: BillingMode;
  ingestedAt: string;
  transactionHash?: string | null;
  success?: boolean;
  errorCode?: string;
  errorReason?: string;
  status?: number;
  radar?: RadarForensics;
};

type RevenueRecord = {
  atomicAmount: string;
  paidSettlements: number;
  updatedAt: string;
};

type AppContext = Context<{ Bindings: Env; Variables: Variables }>;

const ACTIVITY_KEY = 'activity:recent';
const REJECTION_KEY = 'activity:rejections';
const RADAR_KEY = 'activity:radar';
const REVENUE_KEY = 'revenue:total';
const DIRECTORY_PREFIX = 'directory:';
const ACTIVITY_LIMIT = 40;
const DIRECTORY_LIST_LIMIT = 100;
const MAX_SITE_NAME_CHARS = 80;
const MAX_DOMAIN_CHARS = 253;
const MAX_DESCRIPTION_CHARS = 280;
const MAX_UA_CHARS = 512;
const MAX_HEADER_VALUE_CHARS = 256;
const MAX_PATH_CHARS = 512;
const FORENSIC_HEADER_NAMES = [
  'user-agent',
  'cf-connecting-ip',
  'x-forwarded-for',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'accept',
  'accept-language',
  'accept-encoding',
  'referer',
  'origin',
  'content-type',
  'host',
  'x-agent-id',
  'x-owner-id',
] as const;
const BOT_UA_SIGNATURES: Array<{ label: string; pattern: RegExp }> = [
  { label: 'curl', pattern: /\bcurl\//i },
  { label: 'wget', pattern: /\bwget\//i },
  { label: 'python-requests', pattern: /\bpython-requests\//i },
  { label: 'python-urllib', pattern: /\burllib\b/i },
  { label: 'scrapy', pattern: /\bscrapy\b/i },
  { label: 'httpclient', pattern: /\bhttpclient\b/i },
  { label: 'go-http', pattern: /\bgo-http-client\b/i },
  { label: 'axios', pattern: /\baxios\//i },
  { label: 'node-fetch', pattern: /\bnode-fetch\b/i },
  { label: 'undici', pattern: /\bundici\b/i },
  { label: 'postman', pattern: /\bpostmanruntime\b|\bpostman\b/i },
  { label: 'headless-chrome', pattern: /headlesschrome/i },
  { label: 'puppeteer', pattern: /\bpuppeteer\b/i },
  { label: 'playwright', pattern: /\bplaywright\b/i },
  { label: 'selenium', pattern: /\bselenium\b/i },
  { label: 'phantomjs', pattern: /\bphantomjs\b/i },
  { label: 'googlebot', pattern: /\bgooglebot\b/i },
  { label: 'bingbot', pattern: /\bbingbot\b/i },
  { label: 'gptbot', pattern: /\bgptbot\b/i },
  { label: 'claudebot', pattern: /\bclaudebot\b|\banthropic-ai\b/i },
  { label: 'chatgpt', pattern: /\bchatgpt-user\b/i },
  { label: 'ccbot', pattern: /\bccbot\b/i },
  { label: 'bytespider', pattern: /\bbytespider\b/i },
  { label: 'semrush', pattern: /\bsemrushbot\b/i },
  { label: 'ahrefs', pattern: /\bahrefsbot\b/i },
  { label: 'facebook', pattern: /\bfacebookexternalhit\b/i },
  { label: 'generic-bot', pattern: /\b(bot|crawler|spider|scraper)\b/i },
];
const PROBE_PATH_PATTERN =
  /\/(wp-admin|wp-login|xmlrpc\.php|phpmyadmin|\.env|\.git|vendor\/phpunit|actuator|server-status)/i;
const STATIC_PATH_PATTERN = /\.(?:css|js|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|html)$/i;
const ACTIVE_WINDOW_MS = 5 * 60 * 1000;
const IDEMPOTENCY_TTL_SECONDS = 60;
const IDEMPOTENCY_HEADER_MAX = 200;
const USDC_DECIMALS = 6;

function ownerKey(ownerId: string): string {
  return `owner:${ownerId}`;
}

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

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${ms}ms`));
    }, ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function kvGetRaw(kv: KVNamespace, key: string): Promise<string | null> {
  try {
    return await withTimeout(kv.get(key), KV_TIMEOUT_MS, `kv.get:${key}`);
  } catch (error) {
    console.error('[kv] get failed:', error);
    return null;
  }
}

async function kvGetJson<T>(kv: KVNamespace, key: string): Promise<T | null> {
  try {
    const value = await withTimeout(kv.get<T>(key, 'json'), KV_TIMEOUT_MS, `kv.getJson:${key}`);
    return value ?? null;
  } catch (error) {
    console.error('[kv] getJson failed:', error);
    return null;
  }
}

async function kvPutRaw(
  kv: KVNamespace,
  key: string,
  value: string,
  options?: KVNamespacePutOptions,
): Promise<boolean> {
  try {
    await withTimeout(kv.put(key, value, options), KV_TIMEOUT_MS, `kv.put:${key}`);
    return true;
  } catch (error) {
    console.error('[kv] put failed:', error);
    return false;
  }
}

function parseBooleanFlag(value: string | undefined): boolean | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return undefined;
}

const localRateBuckets = new Map<string, { count: number; resetAt: number }>();

function takeLocalRateToken(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  if (localRateBuckets.size > 10_000) {
    for (const [bucketKey, bucket] of localRateBuckets) {
      if (now >= bucket.resetAt) localRateBuckets.delete(bucketKey);
    }
  }
  const bucket = localRateBuckets.get(key);
  if (!bucket || now >= bucket.resetAt) {
    localRateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (bucket.count >= max) return false;
  bucket.count += 1;
  return true;
}

function clientIp(c: Context): string {
  const cfIp = c.req.header('CF-Connecting-IP')?.trim();
  if (cfIp) return cfIp;
  const forwarded = c.req.header('X-Forwarded-For')?.split(',')[0]?.trim();
  if (forwarded) return forwarded;
  return 'unknown';
}

function clampText(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max)}…`;
}

function detectBotSignatures(
  userAgent: string,
  cf: IncomingRequestCfProperties | undefined,
): BotSignature {
  const labels: string[] = [];
  if (!userAgent) labels.push('missing-ua');
  for (const signature of BOT_UA_SIGNATURES) {
    if (signature.pattern.test(userAgent) && !labels.includes(signature.label)) {
      labels.push(signature.label);
    }
  }

  const botManagement = cf?.botManagement;
  const verifiedBot = botManagement?.verifiedBot === true;
  const score = typeof botManagement?.score === 'number' ? botManagement.score : undefined;
  const detectionIds = Array.isArray(botManagement?.detectionIds)
    ? botManagement.detectionIds.filter((id) => Number.isFinite(id))
    : undefined;

  if (verifiedBot && !labels.includes('cf-verified-bot')) labels.push('cf-verified-bot');
  if (typeof score === 'number' && score <= 30 && !labels.includes('cf-likely-bot')) {
    labels.push('cf-likely-bot');
  }

  return {
    labels,
    verifiedBot,
    score,
    detectionIds: detectionIds && detectionIds.length > 0 ? detectionIds : undefined,
  };
}

function collectForensicHeaders(headers: Headers): Record<string, string> {
  const captured: Record<string, string> = {};
  for (const name of FORENSIC_HEADER_NAMES) {
    const value = headers.get(name)?.trim();
    if (value) captured[name] = clampText(value, MAX_HEADER_VALUE_CHARS);
  }
  return captured;
}

function collectRequestForensics(c: Context): RadarForensics {
  let path = '/';
  try {
    const url = new URL(c.req.url);
    path = clampText(`${url.pathname}${url.search}`, MAX_PATH_CHARS);
  } catch {
    path = clampText(c.req.path || '/', MAX_PATH_CHARS);
  }

  const userAgent = clampText(c.req.header('User-Agent')?.trim() ?? '', MAX_UA_CHARS);
  const cf = c.req.raw.cf as IncomingRequestCfProperties | undefined;
  const country = typeof cf?.country === 'string' && cf.country ? cf.country : undefined;
  const asOrganization =
    typeof cf?.asOrganization === 'string' && cf.asOrganization ? cf.asOrganization : undefined;
  const ray = c.req.header('CF-Ray')?.trim();
  let authenticated = false;
  try {
    authenticated = Boolean(resolveAgentId(c as Context<{ Bindings: Env; Variables: Variables }>));
  } catch {
    authenticated = false;
  }

  return {
    method: (c.req.method || 'GET').toUpperCase(),
    path,
    timestamp: new Date().toISOString(),
    sourceIp: clientIp(c),
    userAgent,
    bot: detectBotSignatures(userAgent, cf),
    headers: collectForensicHeaders(c.req.raw.headers),
    authenticated,
    country,
    asOrganization,
    ray: ray ? clampText(ray, MAX_HEADER_VALUE_CHARS) : undefined,
  };
}

function isHudOrStaticTraffic(radar: RadarForensics): boolean {
  if (radar.method === 'OPTIONS') return true;
  if (radar.method !== 'GET' && radar.method !== 'HEAD') return false;
  const path = radar.path.split('?')[0] ?? radar.path;
  if (path === '/' || path === '/index.html') return true;
  if (STATIC_PATH_PATTERN.test(path)) return true;
  if (path === '/api' || path === '/api/') return true;
  if (path.startsWith('/api/telemetry/overview')) return true;
  if (path.startsWith('/api/telemetry/activity')) return true;
  if (path.startsWith('/api/telemetry/status')) return true;
  if (path.startsWith('/api/directory')) return true;
  return false;
}

function isAuthenticatedIngest(radar: RadarForensics): boolean {
  const path = radar.path.split('?')[0] ?? radar.path;
  return radar.method === 'POST' && path === '/api/telemetry' && radar.authenticated;
}

function shouldLogRadarProbe(c: AppContext, radar: RadarForensics): boolean {
  if (isHudOrStaticTraffic(radar)) return false;
  const status = c.res?.status ?? 0;
  const path = radar.path.split('?')[0] ?? radar.path;
  if (isAuthenticatedIngest(radar) && (status < 400 || status === 402)) return false;
  if (path.startsWith('/api/admin/') && status < 400) return false;
  if (!radar.authenticated) return true;
  if (radar.bot.labels.length > 0 && radar.bot.verifiedBot !== true) return true;
  if (status === 401 || status === 403 || status === 404 || status === 429) return true;
  return PROBE_PATH_PATTERN.test(path);
}

function buildRadarEntry(c: AppContext, radar: RadarForensics): ActivityEntry {
  const agentId = resolveAgentId(c) ?? 'anonymous';
  const primaryLabel = radar.bot.labels[0] ?? 'probe';
  return {
    blipId: crypto.randomUUID(),
    agentId,
    event: `radar.${primaryLabel}`,
    billingMode: 'free',
    ingestedAt: radar.timestamp,
    transactionHash: null,
    success: false,
    errorCode: 'RADAR',
    errorReason: `${radar.method} ${radar.path}`,
    status: c.res?.status,
    radar,
  };
}

function scheduleRadarLog(c: AppContext, radar: RadarForensics): void {
  const entry = buildRadarEntry(c, radar);
  c.executionCtx.waitUntil(
    appendRadar(c.env.USAGE_KV, entry).catch((error) => {
      console.error('[radar] persist failed:', error);
    }),
  );
}

function rateLimitKvKey(scope: string, id: string): string {
  const minute = Math.floor(Date.now() / (RATE_LIMIT_WINDOW_SECONDS * 1000));
  return `rl:${scope}:${id}:${minute}`;
}

async function consumeKvRateLimit(kv: KVNamespace, key: string, max: number): Promise<boolean> {
  const raw = await kvGetRaw(kv, key);
  const current = Number.parseInt(raw ?? '0', 10);
  const count = Number.isFinite(current) && current >= 0 ? current : 0;
  if (count >= max) return false;
  await kvPutRaw(kv, key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW_SECONDS * 2 });
  return true;
}

type PaymentAuthorization = {
  from: string;
  to: string;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: string;
};

function sanitizePaymentHeader(
  raw: string,
): { ok: true; value: string } | { ok: false; code: string; message: string } {
  const value = raw.trim();
  if (!value) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT header is empty.' };
  }
  if (value.length > MAX_PAYMENT_HEADER_BYTES) {
    return {
      ok: false,
      code: 'INVALID_PAYMENT',
      message: `X-PAYMENT header exceeds ${MAX_PAYMENT_HEADER_BYTES} bytes.`,
    };
  }
  if (value.includes('\n') || value.includes('\r') || value.includes(' ')) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT header contains invalid whitespace.' };
  }
  if (!PAYMENT_HEADER_CHARSET.test(value)) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT header is not valid base64.' };
  }
  return { ok: true, value };
}

function validatePaymentAuthorization(decoded: {
  payload?: { signature?: string; authorization?: Partial<PaymentAuthorization> };
}): { ok: true; authorization: PaymentAuthorization } | { ok: false; code: string; message: string } {
  const authorization = decoded.payload?.authorization;
  const signature = decoded.payload?.signature;
  if (!authorization || typeof authorization !== 'object') {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT payload is missing authorization.' };
  }
  if (typeof signature !== 'string' || !EVM_SIGNATURE_PATTERN.test(signature)) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT signature is malformed.' };
  }

  const nonce = typeof authorization.nonce === 'string' ? authorization.nonce : '';
  if (!EIP3009_NONCE_PATTERN.test(nonce)) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'EIP-3009 nonce must be a 32-byte hex value.' };
  }

  let from: string;
  let to: string;
  try {
    from = getAddress(String(authorization.from));
    to = getAddress(String(authorization.to));
  } catch {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT authorization addresses are invalid.' };
  }

  let value: bigint;
  let validAfter: bigint;
  let validBefore: bigint;
  try {
    value = BigInt(String(authorization.value));
    validAfter = BigInt(String(authorization.validAfter));
    validBefore = BigInt(String(authorization.validBefore));
  } catch {
    return {
      ok: false,
      code: 'INVALID_PAYMENT',
      message: 'X-PAYMENT authorization numeric fields are invalid.',
    };
  }

  if (value <= 0n) {
    return { ok: false, code: 'INVALID_PAYMENT', message: 'X-PAYMENT authorization value must be positive.' };
  }
  if (validBefore <= validAfter) {
    return {
      ok: false,
      code: 'INVALID_PAYMENT',
      message: 'X-PAYMENT validBefore must be after validAfter.',
    };
  }

  const now = Math.floor(Date.now() / 1000);
  if (validAfter > BigInt(now)) {
    return {
      ok: false,
      code: 'PAYMENT_NOT_YET_VALID',
      message: 'X-PAYMENT authorization validAfter is still in the future.',
    };
  }
  if (validBefore < BigInt(now + PAYMENT_VALID_BEFORE_SKEW_SECONDS)) {
    return {
      ok: false,
      code: 'PAYMENT_EXPIRED',
      message: 'X-PAYMENT authorization validBefore has expired.',
    };
  }
  if (validBefore > BigInt(now + PAYMENT_MAX_FUTURE_SECONDS)) {
    return {
      ok: false,
      code: 'INVALID_PAYMENT',
      message: 'X-PAYMENT authorization validBefore is too far in the future.',
    };
  }

  return {
    ok: true,
    authorization: {
      from,
      to,
      value: value.toString(),
      validAfter: validAfter.toString(),
      validBefore: validBefore.toString(),
      nonce,
    },
  };
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
  return parseUsageRecord(await kvGetRaw(kv, usageKey(agentId)));
}

function defaultFreeTierLimit(env: Env): number {
  return parsePositiveInt(env.FREE_TIER_LIMIT, DEFAULT_FREE_TIER_LIMIT);
}

function defaultPlatformFreeLimit(env: Env): number {
  return parsePositiveInt(env.PLATFORM_FREE_LIMIT, DEFAULT_PLATFORM_FREE_LIMIT);
}

function resolveAgentFreeTierLimit(record: UsageRecord, env: Env): number {
  return record.freeTierLimit && record.freeTierLimit > 0
    ? record.freeTierLimit
    : defaultFreeTierLimit(env);
}

function resolveOwnerId(c: Context<{ Bindings: Env }>): string {
  const headerId = c.req.header('X-Owner-Id')?.trim();
  if (headerId) return headerId;
  const envId = c.env.OWNER_ID?.trim();
  if (envId) return envId;
  return DEFAULT_OWNER_ID;
}

function parseOwnerRecord(ownerId: string, raw: string | null): OwnerRecord {
  if (!raw) return { ownerId, trackedBlips: 0 };
  try {
    const parsed = JSON.parse(raw) as OwnerRecord;
    const trackedBlips = Number(parsed.trackedBlips);
    return {
      ownerId,
      trackedBlips: Number.isFinite(trackedBlips) && trackedBlips >= 0 ? trackedBlips : 0,
      subscriptionActive:
        parsed.subscriptionActive === true ? true : parsed.subscriptionActive === false ? false : undefined,
      lastSeen: typeof parsed.lastSeen === 'string' ? parsed.lastSeen : undefined,
    };
  } catch {
    return { ownerId, trackedBlips: 0 };
  }
}

async function getOwnerRecord(kv: KVNamespace, ownerId: string): Promise<OwnerRecord> {
  return parseOwnerRecord(ownerId, await kvGetRaw(kv, ownerKey(ownerId)));
}

async function putOwnerRecord(kv: KVNamespace, record: OwnerRecord): Promise<boolean> {
  return kvPutRaw(kv, ownerKey(record.ownerId), JSON.stringify(record));
}

function resolveSubscriptionActive(record: OwnerRecord, env: Env): boolean {
  if (record.subscriptionActive === true) return true;
  if (record.subscriptionActive === false) return false;
  return parseBooleanFlag(env.SUBSCRIPTION_ACTIVE) === true;
}

function serializeOwnerSnapshot(record: OwnerRecord, env: Env) {
  const freeLimit = defaultPlatformFreeLimit(env);
  const subscriptionActive = resolveSubscriptionActive(record, env);
  const remainingFreeTracked = Math.max(freeLimit - record.trackedBlips, 0);
  const upgradeRequired = !subscriptionActive && record.trackedBlips >= freeLimit;
  return {
    ownerId: record.ownerId,
    trackedBlips: record.trackedBlips,
    freeLimit,
    remainingFreeTracked,
    subscriptionActive,
    upgradeRequired,
    hudLive: !upgradeRequired,
  };
}

async function incrementOwnerTracked(kv: KVNamespace, ownerId: string): Promise<OwnerRecord> {
  const current = await getOwnerRecord(kv, ownerId);
  const next: OwnerRecord = {
    ...current,
    ownerId,
    trackedBlips: current.trackedBlips + 1,
    lastSeen: new Date().toISOString(),
  };
  await putOwnerRecord(kv, next);
  return next;
}

function directoryKey(nodeId: string): string {
  return `${DIRECTORY_PREFIX}${nodeId}`;
}

function requestOrigin(c: Context): string {
  try {
    const url = new URL(c.req.url);
    const proto = c.req.header('X-Forwarded-Proto')?.split(',')[0]?.trim() || url.protocol.replace(':', '');
    const host = c.req.header('X-Forwarded-Host')?.split(',')[0]?.trim() || c.req.header('Host')?.trim() || url.host;
    const scheme = proto === 'http' ? 'http' : 'https';
    return `${scheme}://${host}`;
  } catch {
    return new URL(c.req.url).origin;
  }
}

function slugifyNodeId(hostname: string): string {
  return hostname.toLowerCase().replace(/[^a-z0-9.-]/g, '-').slice(0, MAX_DOMAIN_CHARS);
}

function parseDirectoryNode(raw: string | null): DirectoryNode | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as DirectoryNode;
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.nodeId !== 'string' || !parsed.nodeId) return null;
    if (typeof parsed.domain !== 'string' || !parsed.domain) return null;
    if (typeof parsed.origin !== 'string' || !parsed.origin) return null;
    return {
      nodeId: parsed.nodeId,
      siteName: typeof parsed.siteName === 'string' && parsed.siteName ? parsed.siteName : parsed.domain,
      domain: parsed.domain,
      origin: parsed.origin,
      description: typeof parsed.description === 'string' ? parsed.description : undefined,
      active: parsed.active !== false,
      optedIn: parsed.optedIn !== false,
      network: typeof parsed.network === 'string' ? parsed.network : DEFAULT_X402_NETWORK,
      currency: typeof parsed.currency === 'string' ? parsed.currency : 'USDC',
      pricePerBlip: typeof parsed.pricePerBlip === 'string' ? parsed.pricePerBlip : DEFAULT_TELEMETRY_PRICE,
      x402Version: Number.isFinite(Number(parsed.x402Version)) ? Number(parsed.x402Version) : X402_VERSION,
      scheme: 'exact',
      facilitatorUrl:
        typeof parsed.facilitatorUrl === 'string' && parsed.facilitatorUrl
          ? parsed.facilitatorUrl
          : DEFAULT_FACILITATOR_URL,
      ingestUrl: typeof parsed.ingestUrl === 'string' ? parsed.ingestUrl : `${parsed.origin}/api/telemetry`,
      statusUrl: typeof parsed.statusUrl === 'string' ? parsed.statusUrl : `${parsed.origin}/api/telemetry/status`,
      directoryUrl: typeof parsed.directoryUrl === 'string' ? parsed.directoryUrl : `${parsed.origin}/api/directory`,
      ownerId: typeof parsed.ownerId === 'string' ? parsed.ownerId : undefined,
      registeredAt: typeof parsed.registeredAt === 'string' ? parsed.registeredAt : new Date().toISOString(),
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : new Date().toISOString(),
      lastSeen: typeof parsed.lastSeen === 'string' ? parsed.lastSeen : undefined,
    };
  } catch {
    return null;
  }
}

function serializeDirectoryNode(node: DirectoryNode) {
  return {
    nodeId: node.nodeId,
    siteName: node.siteName,
    domain: node.domain,
    origin: node.origin,
    description: node.description ?? null,
    status: node.active ? 'active' : 'inactive',
    active: node.active,
    optedIn: node.optedIn,
    network: node.network,
    currency: node.currency,
    pricePerBlip: node.pricePerBlip,
    x402Version: node.x402Version,
    scheme: node.scheme,
    facilitatorUrl: node.facilitatorUrl,
    endpoints: {
      ingest: node.ingestUrl,
      status: node.statusUrl,
      directory: node.directoryUrl,
    },
    ownerId: node.ownerId ?? null,
    lastSeen: node.lastSeen ?? null,
    registeredAt: node.registeredAt,
    updatedAt: node.updatedAt,
  };
}

function buildSelfDirectoryNode(c: AppContext): DirectoryNode {
  const origin = requestOrigin(c);
  let hostname = origin;
  try {
    hostname = new URL(origin).hostname;
  } catch {
    hostname = origin.replace(/^https?:\/\//, '');
  }
  const now = new Date().toISOString();
  return {
    nodeId: slugifyNodeId(hostname) || 'self',
    siteName: 'Tollbase',
    domain: hostname,
    origin,
    description: 'Real-time telemetry HUD for autonomous agent loops.',
    active: true,
    optedIn: true,
    network: resolveX402Network(c.env),
    currency: 'USDC',
    pricePerBlip: resolveTelemetryPrice(c.env),
    x402Version: X402_VERSION,
    scheme: 'exact',
    facilitatorUrl: resolveFacilitatorUrl(c.env),
    ingestUrl: `${origin}/api/telemetry`,
    statusUrl: `${origin}/api/telemetry/status`,
    directoryUrl: `${origin}/api/directory`,
    ownerId: resolveOwnerId(c),
    registeredAt: now,
    updatedAt: now,
    lastSeen: now,
  };
}

function normalizeSiteDomain(input: string): { ok: true; hostname: string; origin: string } | { ok: false; message: string } {
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > MAX_DOMAIN_CHARS + 32) {
    return { ok: false, message: 'domain must be a hostname or https URL.' };
  }
  if (/[\s\\\\]/.test(trimmed) || trimmed.includes('@') || trimmed.includes(':///') ) {
    return { ok: false, message: 'domain contains invalid characters.' };
  }
  try {
    const url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { ok: false, message: 'domain must use http or https.' };
    }
    const hostname = url.hostname.toLowerCase();
    if (!hostname || hostname.length > MAX_DOMAIN_CHARS) {
      return { ok: false, message: 'domain hostname is invalid.' };
    }
    if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$|^[a-z0-9]$/.test(hostname)) {
      return { ok: false, message: 'domain hostname is invalid.' };
    }
    return { ok: true, hostname, origin: url.origin };
  } catch {
    return { ok: false, message: 'domain must be a hostname or https URL.' };
  }
}

function nodeMatchesQuery(node: DirectoryNode, query: string): boolean {
  if (!query) return true;
  const haystack = [node.siteName, node.domain, node.origin, node.description ?? '', node.nodeId]
    .join(' ')
    .toLowerCase();
  return haystack.includes(query);
}

async function listDirectoryNodes(kv: KVNamespace): Promise<DirectoryNode[]> {
  const nodes: DirectoryNode[] = [];
  let cursor: string | undefined;
  try {
    do {
      const page = await withTimeout(
        kv.list({ prefix: DIRECTORY_PREFIX, cursor, limit: 100 }),
        KV_LIST_TIMEOUT_MS,
        'kv.list:directory',
      );
      const records = await Promise.all(
        page.keys.map(async (key) => parseDirectoryNode(await kvGetRaw(kv, key.name))),
      );
      for (const record of records) {
        if (record) nodes.push(record);
      }
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
  } catch (error) {
    console.error('[kv] list directory failed:', error);
  }
  return nodes;
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

async function requireAdmin(
  c: Context<{ Bindings: Env }>,
): Promise<Response | null> {
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

  return null;
}

async function getUsageCount(kv: KVNamespace, agentId: string): Promise<number> {
  const record = await getUsageRecord(kv, agentId);
  return record.count;
}

async function putUsageRecord(kv: KVNamespace, agentId: string, record: UsageRecord): Promise<void> {
  await kvPutRaw(kv, usageKey(agentId), JSON.stringify(record));
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
    const previous = await kvGetRaw(env.USAGE_KV, lastAlertKey(agentId));
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

    await kvPutRaw(env.USAGE_KV, lastAlertKey(agentId), alertedAt, {
      expirationTtl: Math.ceil(ALERT_COOLDOWN_MS / 1000),
    });
  } catch (error) {
    console.error('[alert] low-balance notification failed:', error);
  }
}

function parseAtomicAmount(value: string | undefined): bigint {
  if (!value) return 0n;
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

function formatAtomicUsdc(atomic: string, decimals = USDC_DECIMALS): string {
  const negative = atomic.startsWith('-');
  const digits = (negative ? atomic.slice(1) : atomic).replace(/^0+/, '') || '0';
  const padded = digits.padStart(decimals + 1, '0');
  const whole = padded.slice(0, -decimals);
  const frac = padded.slice(-decimals).replace(/0+$/, '');
  const formatted = frac.length > 0 ? `${whole}.${frac}` : whole;
  return negative ? `-${formatted}` : formatted;
}

function emptyRevenue(): RevenueRecord {
  return { atomicAmount: '0', paidSettlements: 0, updatedAt: new Date().toISOString() };
}

async function readRevenue(kv: KVNamespace): Promise<RevenueRecord> {
  const raw = await kvGetRaw(kv, REVENUE_KEY);
  if (!raw) return emptyRevenue();
  try {
    const parsed = JSON.parse(raw) as RevenueRecord;
    const paidSettlements = Number(parsed.paidSettlements);
    return {
      atomicAmount: parseAtomicAmount(parsed.atomicAmount).toString(),
      paidSettlements: Number.isFinite(paidSettlements) && paidSettlements >= 0 ? paidSettlements : 0,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : emptyRevenue().updatedAt,
    };
  } catch {
    return emptyRevenue();
  }
}

async function incrementRevenue(kv: KVNamespace, atomicDelta: string): Promise<RevenueRecord> {
  const current = await readRevenue(kv);
  const next: RevenueRecord = {
    atomicAmount: (parseAtomicAmount(current.atomicAmount) + parseAtomicAmount(atomicDelta)).toString(),
    paidSettlements: current.paidSettlements + 1,
    updatedAt: new Date().toISOString(),
  };
  await kvPutRaw(kv, REVENUE_KEY, JSON.stringify(next));
  return next;
}

async function readActivityList(kv: KVNamespace, key: string): Promise<ActivityEntry[]> {
  const raw = await kvGetRaw(kv, key);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw) as ActivityEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function appendCappedActivity(kv: KVNamespace, key: string, entry: ActivityEntry): Promise<void> {
  const recent = await readActivityList(kv, key);
  recent.unshift(entry);
  await kvPutRaw(kv, key, JSON.stringify(recent.slice(0, ACTIVITY_LIMIT)));
}

async function appendActivity(kv: KVNamespace, entry: ActivityEntry): Promise<void> {
  const key = entry.success === false ? REJECTION_KEY : ACTIVITY_KEY;
  await appendCappedActivity(kv, key, { ...entry, success: entry.success !== false });
}

async function appendRadar(kv: KVNamespace, entry: ActivityEntry): Promise<void> {
  await appendCappedActivity(kv, RADAR_KEY, entry);
}

async function attachActivityTransaction(
  kv: KVNamespace,
  blipId: string,
  transactionHash: string,
): Promise<void> {
  const recent = await readActivityList(kv, ACTIVITY_KEY);
  const index = recent.findIndex((entry) => entry.blipId === blipId);
  if (index < 0) return;
  recent[index] = { ...recent[index], transactionHash };
  await kvPutRaw(kv, ACTIVITY_KEY, JSON.stringify(recent));
}

async function moveActivityToRejection(
  kv: KVNamespace,
  blipId: string,
  errorCode: string,
  errorReason: string,
): Promise<void> {
  const recent = await readActivityList(kv, ACTIVITY_KEY);
  const index = recent.findIndex((entry) => entry.blipId === blipId);
  if (index < 0) return;
  const [entry] = recent.splice(index, 1);
  await kvPutRaw(kv, ACTIVITY_KEY, JSON.stringify(recent));
  await appendActivity(kv, {
    ...entry,
    success: false,
    errorCode,
    errorReason,
    status: 402,
  });
}

async function readRecentActivity(kv: KVNamespace): Promise<ActivityEntry[]> {
  return (await readActivityList(kv, ACTIVITY_KEY)).filter((entry) => entry.success !== false);
}

async function readRecentRejections(kv: KVNamespace): Promise<ActivityEntry[]> {
  return (await readActivityList(kv, REJECTION_KEY)).filter((entry) => entry.success === false);
}

async function readRecentRadar(kv: KVNamespace): Promise<ActivityEntry[]> {
  return readActivityList(kv, RADAR_KEY);
}

function resolveRejectionEvent(c: AppContext): string {
  const body = c.get('telemetryBody');
  return body && typeof body.event === 'string' && body.event.length > 0 ? body.event : 'telemetry';
}

function scheduleRejectionLog(
  c: AppContext,
  params: { code: string; message: string; agentId?: string },
): void {
  const agentId = params.agentId ?? c.get('agentId') ?? resolveAgentId(c) ?? 'anonymous';
  const entry: ActivityEntry = {
    blipId: crypto.randomUUID(),
    agentId,
    event: resolveRejectionEvent(c),
    billingMode: 'paid',
    ingestedAt: new Date().toISOString(),
    transactionHash: null,
    success: false,
    errorCode: params.code,
    errorReason: params.message,
    status: 402,
    radar: c.get('radar'),
  };
  c.executionCtx.waitUntil(
    appendActivity(c.env.USAGE_KV, entry).catch((error) => {
      console.error('[activity] failed to log rejection:', error);
    }),
  );
}

function utf8ToBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

function resolveTelemetryPrice(env: Env): string {
  return env.TELEMETRY_PRICE?.trim() || DEFAULT_TELEMETRY_PRICE;
}

function resolveX402Network(env: Env): Network {
  return (env.X402_NETWORK?.trim() || DEFAULT_X402_NETWORK) as Network;
}

function resolveFacilitatorUrl(env: Env): string {
  return env.X402_FACILITATOR_URL?.trim() || DEFAULT_FACILITATOR_URL;
}

function applyX402ChallengeHeaders(
  c: AppContext,
  params: {
    accepts: unknown;
    error: string;
    price: string;
    network: string;
    facilitatorUrl: string;
  },
): void {
  c.header('X-Payment-Required', 'x402');
  c.header('X-x402-Version', String(X402_VERSION));
  c.header('X-Payment-Amount', params.price);
  c.header('X-Payment-Currency', 'USDC');
  c.header('X-Payment-Network', params.network);
  c.header('X-Payment-Facilitator', params.facilitatorUrl);
  try {
    c.header(
      'PAYMENT-REQUIRED',
      utf8ToBase64(
        JSON.stringify({
          x402Version: X402_VERSION,
          accepts: params.accepts,
          error: params.error,
        }),
      ),
    );
  } catch (error) {
    console.error('[x402] failed to encode PAYMENT-REQUIRED header:', error);
  }
}

function paymentRequiredResponse(
  c: AppContext,
  body: {
    status: 'payment_required';
    code: string;
    message: string;
    agentId?: string;
    usageCount?: number;
    freeTierLimit?: number;
    x402Version: number;
    accepts: unknown;
    payer?: string;
  },
) {
  const price = resolveTelemetryPrice(c.env);
  const network = resolveX402Network(c.env);
  const facilitatorUrl = resolveFacilitatorUrl(c.env);
  const accepts =
    body.accepts && typeof body.accepts === 'object'
      ? toJsonSafe(body.accepts as object)
      : [];
  applyX402ChallengeHeaders(c, {
    accepts,
    error: body.message,
    price,
    network,
    facilitatorUrl,
  });
  scheduleRejectionLog(c, { code: body.code, message: body.message, agentId: body.agentId });
  return c.json(
    {
      ...body,
      accepts,
      error: body.message,
      pricePerBlip: price,
      currency: 'USDC',
      network,
      facilitatorUrl,
    },
    402,
  );
}

async function listAgentUsage(kv: KVNamespace): Promise<Array<{ agentId: string; record: UsageRecord }>> {
  const agents: Array<{ agentId: string; record: UsageRecord }> = [];
  let cursor: string | undefined;

  try {
    do {
      const page = await withTimeout(
        kv.list({ prefix: 'usage:', cursor }),
        KV_LIST_TIMEOUT_MS,
        'kv.list:usage',
      );
      const records = await Promise.all(
        page.keys.map(async (key) => {
          const agentId = key.name.slice('usage:'.length);
          return { agentId, record: parseUsageRecord(await kvGetRaw(kv, key.name)) };
        }),
      );
      agents.push(...records);
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
  } catch (error) {
    console.error('[kv] list usage failed:', error);
  }

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
      description: 'Tollbase telemetry blip ingestion',
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
  blipId = crypto.randomUUID(),
  radar?: RadarForensics,
): Promise<{ blipId: string; persisted: boolean }> {
  const record = {
    id: blipId,
    agent_id: agentId,
    event: blip.event,
    payload: blip.payload ?? {},
    session_id: blip.sessionId ?? null,
    metadata: {
      ...(blip.metadata ?? {}),
      ...(radar ? { radar } : {}),
    },
    billing_mode: billingMode,
    client_timestamp: blip.timestamp ?? null,
    ingested_at: new Date().toISOString(),
  };

  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.log('[telemetry:local]', JSON.stringify(record));
    return { blipId, persisted: false };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SUPABASE_TIMEOUT_MS);

  try {
    const response = await fetch(`${env.SUPABASE_URL}/rest/v1/telemetry_blips`, {
      method: 'POST',
      headers: {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal',
      },
      body: JSON.stringify(record),
      signal: controller.signal,
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      console.error('[telemetry] supabase ingest failed:', response.status, detail);
      return { blipId, persisted: false };
    }

    return { blipId, persisted: true };
  } catch (error) {
    console.error('[telemetry] supabase ingest failed:', error);
    return { blipId, persisted: false };
  } finally {
    clearTimeout(timer);
  }
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

function createTelemetryAbuseGate(): MiddlewareHandler<{
  Bindings: Env;
  Variables: Variables;
}> {
  return async (c, next) => {
    const perAgent = parsePositiveInt(c.env.RATE_LIMIT_PER_AGENT, DEFAULT_RATE_LIMIT_PER_AGENT);
    const perIp = parsePositiveInt(c.env.RATE_LIMIT_PER_IP, DEFAULT_RATE_LIMIT_PER_IP);
    const windowMs = RATE_LIMIT_WINDOW_SECONDS * 1000;
    const ip = clientIp(c);
    const agentId = resolveAgentId(c) ?? 'anonymous';

    if (!takeLocalRateToken(`ip:${ip}`, perIp, windowMs) || !takeLocalRateToken(`agent:${agentId}`, perAgent, windowMs)) {
      c.header('Retry-After', String(RATE_LIMIT_WINDOW_SECONDS));
      return c.json(
        {
          status: 'error',
          code: 'RATE_LIMITED',
          message: `Too many telemetry requests. Retry after ${RATE_LIMIT_WINDOW_SECONDS} seconds.`,
        },
        429,
      );
    }

    const [ipAllowed, agentAllowed] = await Promise.all([
      consumeKvRateLimit(c.env.USAGE_KV, rateLimitKvKey('ip', ip), perIp),
      consumeKvRateLimit(c.env.USAGE_KV, rateLimitKvKey('agent', agentId), perAgent),
    ]);
    if (!ipAllowed || !agentAllowed) {
      c.header('Retry-After', String(RATE_LIMIT_WINDOW_SECONDS));
      return c.json(
        {
          status: 'error',
          code: 'RATE_LIMITED',
          message: `Too many telemetry requests. Retry after ${RATE_LIMIT_WINDOW_SECONDS} seconds.`,
        },
        429,
      );
    }

    const contentLengthHeader = c.req.header('Content-Length');
    if (contentLengthHeader) {
      const contentLength = Number.parseInt(contentLengthHeader, 10);
      if (Number.isFinite(contentLength) && contentLength > MAX_TELEMETRY_BODY_BYTES) {
        return c.json(
          {
            status: 'error',
            code: 'PAYLOAD_TOO_LARGE',
            message: `Telemetry body exceeds ${MAX_TELEMETRY_BODY_BYTES} bytes.`,
          },
          413,
        );
      }
    }

    return next();
  };
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

    if (new TextEncoder().encode(rawBody).byteLength > MAX_TELEMETRY_BODY_BYTES) {
      return c.json(
        {
          status: 'error',
          code: 'PAYLOAD_TOO_LARGE',
          message: `Telemetry body exceeds ${MAX_TELEMETRY_BODY_BYTES} bytes.`,
        },
        413,
      );
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

    const cache = await kvGetJson<IdempotencyCache>(
      c.env.USAGE_KV,
      idempotencyKvKey(agentId, idempotencyKey),
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
      await kvPutRaw(c.env.USAGE_KV, idempotencyKvKey(agentId, idempotencyKey), JSON.stringify(record), {
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

    // Free allowance still available — increment, then re-check so concurrent
    // admits cannot silently overshoot the default usage limit.
    if (usageCount < freeTierLimit) {
      try {
        const updatedCount = await incrementUsageCount(c.env.USAGE_KV, agentId);
        if (updatedCount <= freeTierLimit) {
          c.set('usageCount', updatedCount);
          c.set('billingMode', 'free');
          return next();
        }
        const latest = await getUsageRecord(c.env.USAGE_KV, agentId);
        await putUsageRecord(c.env.USAGE_KV, agentId, {
          ...latest,
          count: freeTierLimit,
          billingMode: 'paid',
          lastSeen: new Date().toISOString(),
        });
        c.set('usageCount', freeTierLimit);
      } catch (error) {
        console.error('[kv] usage increment failed:', error);
        c.set('usageCount', usageCount + 1);
        c.set('billingMode', 'free');
        return next();
      }
    }

    // Allowance exhausted — enforce x402 micro-settlement immediately.
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

    const network = resolveX402Network(c.env);
    const price = resolveTelemetryPrice(c.env);
    const facilitatorUrl = resolveFacilitatorUrl(c.env) as Resource;

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
    const paymentHeaderRaw = c.req.header('X-PAYMENT');
    const exhaustedUsage = c.get('usageCount');

    if (!paymentHeaderRaw) {
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: 'FREE_TIER_EXHAUSTED',
        message: `Free telemetry allowance exhausted (${freeTierLimit} blips). Retry with an X-PAYMENT header to settle ${price} USDC on ${network}.`,
        agentId,
        usageCount: exhaustedUsage,
        freeTierLimit,
        x402Version: X402_VERSION,
        accepts: paymentRequirements,
      });
    }

    const sanitizedHeader = sanitizePaymentHeader(paymentHeaderRaw);
    if (!sanitizedHeader.ok) {
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: sanitizedHeader.code,
        message: sanitizedHeader.message,
        x402Version: X402_VERSION,
        accepts: paymentRequirements,
      });
    }

    let decodedPayment;
    try {
      decodedPayment = exact.evm.decodePayment(sanitizedHeader.value);
      decodedPayment.x402Version = X402_VERSION;
    } catch (error) {
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: 'INVALID_PAYMENT',
        message: error instanceof Error ? error.message : 'Invalid or malformed X-PAYMENT header',
        x402Version: X402_VERSION,
        accepts: paymentRequirements,
      });
    }

    const authorizationCheck = validatePaymentAuthorization(decodedPayment);
    if (!authorizationCheck.ok) {
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: authorizationCheck.code,
        message: authorizationCheck.message,
        x402Version: X402_VERSION,
        accepts: paymentRequirements,
      });
    }

    const selectedRequirements = findMatchingPaymentRequirements(
      paymentRequirements,
      decodedPayment,
    );

    if (!selectedRequirements) {
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: 'NO_MATCHING_REQUIREMENTS',
        message: 'Unable to find matching payment requirements for the supplied X-PAYMENT header.',
        x402Version: X402_VERSION,
        accepts: toJsonSafe(paymentRequirements),
      });
    }

    const { verify, settle } = useFacilitator({ url: facilitatorUrl });

    try {
      const verification = await verify(decodedPayment, selectedRequirements);
      if (!verification.isValid) {
        return paymentRequiredResponse(c, {
          status: 'payment_required',
          code: 'VERIFICATION_FAILED',
          message: verification.invalidReason ?? 'Payment verification failed',
          payer: typeof verification.payer === 'string' ? verification.payer : undefined,
          x402Version: X402_VERSION,
          accepts: paymentRequirements,
        });
      }
    } catch (error) {
      console.error('[x402] verification error:', error);
      return paymentRequiredResponse(c, {
        status: 'payment_required',
        code: 'VERIFICATION_ERROR',
        message: error instanceof Error ? error.message : 'Payment verification failed',
        x402Version: X402_VERSION,
        accepts: paymentRequirements,
      });
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

      const transactionHash = typeof settlement.transaction === 'string' ? settlement.transaction : '';
      const paymentResponseHeader = settleResponseHeader(settlement);
      let bodyText = await response.clone().text();
      try {
        const payload = JSON.parse(bodyText) as Record<string, unknown>;
        if (payload && typeof payload === 'object') {
          bodyText = JSON.stringify({
            ...payload,
            transactionHash: transactionHash || null,
            billingMode: 'paid',
          });
        }
      } catch (error) {
        console.error('[x402] failed to enrich settlement response body:', error);
      }

      const settledResponse = new Response(bodyText, {
        status: response.status,
        headers: new Headers(response.headers),
      });
      settledResponse.headers.set('X-PAYMENT-RESPONSE', paymentResponseHeader);
      settledResponse.headers.set('Content-Type', 'application/json');
      c.res = settledResponse;

      const blipId = c.get('blipId');
      const atomicAmount = processPriceToAtomicAmount(price, network);
      const ownerId = resolveOwnerId(c);
      await Promise.allSettled([
        blipId && transactionHash
          ? attachActivityTransaction(c.env.USAGE_KV, blipId, transactionHash)
          : Promise.resolve(),
        !('error' in atomicAmount)
          ? incrementRevenue(c.env.USAGE_KV, String(atomicAmount.maxAmountRequired))
          : Promise.resolve(),
        incrementOwnerTracked(c.env.USAGE_KV, ownerId),
      ]);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to settle payment on-chain';
      const blipId = c.get('blipId');
      c.executionCtx.waitUntil(
        (blipId
          ? moveActivityToRejection(c.env.USAGE_KV, blipId, 'SETTLEMENT_FAILED', message)
          : appendActivity(c.env.USAGE_KV, {
              blipId: crypto.randomUUID(),
              agentId,
              event: resolveRejectionEvent(c),
              billingMode: 'paid',
              ingestedAt: new Date().toISOString(),
              transactionHash: null,
              success: false,
              errorCode: 'SETTLEMENT_FAILED',
              errorReason: message,
              status: 402,
              radar: c.get('radar'),
            })
        ).catch((logError) => {
          console.error('[activity] failed to log settlement failure:', logError);
        }),
      );
      applyX402ChallengeHeaders(c, {
        accepts: toJsonSafe(paymentRequirements),
        error: message,
        price,
        network,
        facilitatorUrl,
      });
      c.res = c.json(
        {
          status: 'payment_required',
          code: 'SETTLEMENT_FAILED',
          message,
          error: message,
          x402Version: X402_VERSION,
          accepts: toJsonSafe(paymentRequirements),
          pricePerBlip: price,
          currency: 'USDC',
          network,
          facilitatorUrl,
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
    allowHeaders: ['Content-Type', 'X-Agent-Id', 'X-Owner-Id', 'X-PAYMENT', 'X-Admin-Key', 'Authorization', 'X-Idempotency-Key'],
    exposeHeaders: [
      'X-PAYMENT-RESPONSE',
      'X-Idempotency-Replayed',
      'PAYMENT-REQUIRED',
      'X-Payment-Required',
      'X-x402-Version',
      'X-Payment-Amount',
      'X-Payment-Currency',
      'X-Payment-Network',
      'X-Payment-Facilitator',
    ],
  }),
);

app.use('*', async (c, next) => {
  let radar: RadarForensics | undefined;
  try {
    radar = collectRequestForensics(c);
    c.set('radar', radar);
  } catch (error) {
    console.error('[radar] collect failed:', error);
  }

  try {
    await next();
  } finally {
    if (radar) {
      try {
        if (shouldLogRadarProbe(c, radar)) scheduleRadarLog(c, radar);
      } catch (error) {
        console.error('[radar] schedule failed:', error);
      }
    }
  }
});

app.get('/api', (c) => {
  return c.json({
    project: 'Tollbase',
    status: 'online',
    message: 'Real-time telemetry HUD and monitoring sink for autonomous AI agent loops.',
    protocol: 'x402',
    endpoints: {
      telemetry: 'POST /api/telemetry',
      telemetryStatus: 'GET /api/telemetry/status',
      telemetryOverview: 'GET /api/telemetry/overview',
      telemetryActivity: 'GET /api/telemetry/activity',
      directory: 'GET /api/directory',
      directoryNode: 'GET /api/directory/:nodeId',
      adminAgent: 'POST /api/admin/agent',
      adminOwner: 'POST /api/admin/owner',
      adminDirectory: 'POST /api/admin/directory',
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

  const recent = await readRecentActivity(c.env.USAGE_KV);
  const rejections = await readRecentRejections(c.env.USAGE_KV);
  const radar = await readRecentRadar(c.env.USAGE_KV);
  const revenue = await readRevenue(c.env.USAGE_KV);
  const owner = await getOwnerRecord(c.env.USAGE_KV, resolveOwnerId(c));
  const platform = serializeOwnerSnapshot(owner, c.env);

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
    platform,
    totals: {
      agents: agents.length,
      activeAgents,
      usageCount,
      remainingFreeBlips,
      paidAgents,
      blockedAgents,
      settlementStatus: paidAgents > 0 ? 'x402_required' : 'free_tier',
      revenueUsdc: formatAtomicUsdc(revenue.atomicAmount),
      revenueAtomic: revenue.atomicAmount,
      paidSettlements: revenue.paidSettlements,
      trackedBlips: platform.trackedBlips,
    },
    agents: platform.hudLive ? agents : [],
    recent: platform.hudLive ? recent : [],
    rejections: platform.hudLive ? rejections : [],
    radar,
  });
});

app.get('/api/telemetry/activity', async (c) => {
  const limit = parsePositiveInt(c.req.query('limit'), 25);
  const cap = Math.min(limit, ACTIVITY_LIMIT);
  const owner = await getOwnerRecord(c.env.USAGE_KV, resolveOwnerId(c));
  const platform = serializeOwnerSnapshot(owner, c.env);
  const events = platform.hudLive
    ? (await readRecentActivity(c.env.USAGE_KV)).slice(0, cap)
    : [];
  const rejections = platform.hudLive
    ? (await readRecentRejections(c.env.USAGE_KV)).slice(0, cap)
    : [];
  const radar = (await readRecentRadar(c.env.USAGE_KV)).slice(0, cap);
  return c.json({
    status: 'success',
    protocol: 'x402',
    network: c.env.X402_NETWORK ?? DEFAULT_X402_NETWORK,
    platform,
    events,
    rejections,
    radar,
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

app.post('/api/telemetry', createTelemetryAbuseGate(), createTelemetryIdempotencyGate(), createTelemetryPaymentGate(), async (c) => {
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

  if (!body.event || typeof body.event !== 'string' || body.event.length > MAX_EVENT_CHARS) {
    return c.json(
      {
        status: 'error',
        code: 'INVALID_EVENT',
        message: `Telemetry payload must include a string "event" field (max ${MAX_EVENT_CHARS} characters).`,
      },
      400,
    );
  }

  const agentId = c.get('agentId');
  const billingMode = c.get('billingMode');
  const ownerId = resolveOwnerId(c);
  const blipId = crypto.randomUUID();
  const radar = c.get('radar');
  c.set('blipId', blipId);

  const { persisted } = await persistTelemetryBlip(c.env, agentId, body, billingMode, blipId, radar);

  await Promise.allSettled([
    touchUsageRecord(c.env.USAGE_KV, agentId, {
      lastEvent: body.event,
      billingMode,
    }),
    appendActivity(c.env.USAGE_KV, {
      blipId,
      agentId,
      event: body.event,
      billingMode,
      ingestedAt: radar?.timestamp ?? new Date().toISOString(),
      transactionHash: null,
      success: true,
      radar,
    }),
    billingMode === 'free' ? incrementOwnerTracked(c.env.USAGE_KV, ownerId) : Promise.resolve(),
  ]);

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
    ownerId,
    event: body.event,
    billingMode,
    persisted,
    usageCount,
    freeTierLimit,
    ingestedAt: radar?.timestamp ?? new Date().toISOString(),
    transactionHash: null,
  });
});

app.post('/api/admin/agent', async (c) => {
  const unauthorized = await requireAdmin(c);
  if (unauthorized) return unauthorized;

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

app.post('/api/admin/owner', async (c) => {
  const unauthorized = await requireAdmin(c);
  if (unauthorized) return unauthorized;

  let body: AdminOwnerBody = {};
  const contentType = c.req.header('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    try {
      body = await c.req.json<AdminOwnerBody>();
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

  const ownerId = resolveOwnerId(c);
  const record = await getOwnerRecord(c.env.USAGE_KV, ownerId);
  const applied: string[] = [];

  if (body.action === 'subscribe' || body.subscriptionActive === true) {
    record.subscriptionActive = true;
    applied.push('subscribe');
  }

  if (body.action === 'unsubscribe' || body.subscriptionActive === false) {
    record.subscriptionActive = false;
    applied.push('unsubscribe');
  }

  if (body.action === 'reset_tracked' || body.resetTracked === true) {
    record.trackedBlips = 0;
    applied.push('resetTracked');
  }

  if (applied.length === 0) {
    return c.json(
      {
        status: 'error',
        code: 'NO_ADMIN_ACTION',
        message: 'Specify action: subscribe, unsubscribe, or reset_tracked.',
      },
      400,
    );
  }

  record.lastSeen = new Date().toISOString();
  await putOwnerRecord(c.env.USAGE_KV, record);

  return c.json({
    status: 'success',
    applied,
    platform: serializeOwnerSnapshot(record, c.env),
  });
});

app.get('/api/directory', async (c) => {
  const query = (c.req.query('q') ?? '').trim().toLowerCase();
  const includeInactive = parseBooleanFlag(c.req.query('includeInactive')) === true;
  const limit = Math.min(parsePositiveInt(c.req.query('limit'), 50), DIRECTORY_LIST_LIMIT);
  const self = buildSelfDirectoryNode(c);
  const stored = await listDirectoryNodes(c.env.USAGE_KV);
  const byId = new Map<string, DirectoryNode>();
  for (const node of stored) byId.set(node.nodeId, node);
  const existing = byId.get(self.nodeId);
  byId.set(
    self.nodeId,
    existing
      ? {
          ...self,
          ...existing,
          origin: self.origin,
          ingestUrl: self.ingestUrl,
          statusUrl: self.statusUrl,
          directoryUrl: self.directoryUrl,
          network: self.network,
          currency: self.currency,
          pricePerBlip: self.pricePerBlip,
          facilitatorUrl: self.facilitatorUrl,
          lastSeen: self.lastSeen,
        }
      : self,
  );

  let nodes = [...byId.values()].filter((node) => node.optedIn);
  if (!includeInactive) nodes = nodes.filter((node) => node.active);
  if (query) nodes = nodes.filter((node) => nodeMatchesQuery(node, query));
  nodes.sort((a, b) => a.siteName.localeCompare(b.siteName) || a.domain.localeCompare(b.domain));
  const page = nodes.slice(0, limit);

  c.header('Cache-Control', 'public, max-age=15, stale-while-revalidate=60');
  return c.json({
    status: 'success',
    protocol: 'x402',
    crawler: {
      protocol: 'x402',
      version: X402_VERSION,
      network: resolveX402Network(c.env),
      currency: 'USDC',
      paymentHeader: 'X-PAYMENT',
      agentHeader: 'X-Agent-Id',
      ingest: 'POST /api/telemetry',
    },
    query: query || null,
    count: page.length,
    total: nodes.length,
    nodes: page.map(serializeDirectoryNode),
  });
});

app.get('/api/directory/:nodeId', async (c) => {
  const nodeId = slugifyNodeId(c.req.param('nodeId') ?? '');
  if (!nodeId) {
    return c.json({ status: 'error', code: 'INVALID_NODE', message: 'nodeId is required.' }, 400);
  }

  const stored = parseDirectoryNode(await kvGetRaw(c.env.USAGE_KV, directoryKey(nodeId)));
  const self = buildSelfDirectoryNode(c);
  const node = stored ?? (self.nodeId === nodeId ? self : null);
  if (!node || !node.optedIn || !node.active) {
    return c.json({ status: 'error', code: 'NODE_NOT_FOUND', message: 'No active opted-in directory node with that id.' }, 404);
  }

  c.header('Cache-Control', 'public, max-age=15, stale-while-revalidate=60');
  return c.json({
    status: 'success',
    protocol: 'x402',
    node: serializeDirectoryNode(node.nodeId === self.nodeId ? { ...node, ...self, siteName: node.siteName, description: node.description } : node),
  });
});

app.post('/api/admin/directory', async (c) => {
  const unauthorized = await requireAdmin(c);
  if (unauthorized) return unauthorized;

  let body: DirectoryAdminBody = {};
  const contentType = c.req.header('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    try {
      body = await c.req.json<DirectoryAdminBody>();
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

  const action = body.action ?? 'register';
  const domainInput = typeof body.domain === 'string' ? body.domain : '';
  const parsedDomain = normalizeSiteDomain(domainInput);
  if (!parsedDomain.ok) {
    return c.json({ status: 'error', code: 'INVALID_DOMAIN', message: parsedDomain.message }, 400);
  }

  const nodeId = slugifyNodeId(parsedDomain.hostname);
  const now = new Date().toISOString();
  const current = parseDirectoryNode(await kvGetRaw(c.env.USAGE_KV, directoryKey(nodeId)));
  const siteName =
    typeof body.siteName === 'string' && body.siteName.trim()
      ? body.siteName.trim().slice(0, MAX_SITE_NAME_CHARS)
      : current?.siteName ?? parsedDomain.hostname;
  const description =
    typeof body.description === 'string'
      ? body.description.trim().slice(0, MAX_DESCRIPTION_CHARS) || undefined
      : current?.description;
  const ingestPath =
    typeof body.ingestPath === 'string' && body.ingestPath.startsWith('/')
      ? body.ingestPath
      : '/api/telemetry';

  if (action === 'register' || action === 'update' || action === 'activate' || action === 'deactivate') {
    const active =
      action === 'deactivate' ? false : action === 'activate' ? true : body.active !== false;
    const node: DirectoryNode = {
      nodeId,
      siteName,
      domain: parsedDomain.hostname,
      origin: parsedDomain.origin,
      description,
      active,
      optedIn: true,
      network: resolveX402Network(c.env),
      currency: 'USDC',
      pricePerBlip: resolveTelemetryPrice(c.env),
      x402Version: X402_VERSION,
      scheme: 'exact',
      facilitatorUrl: resolveFacilitatorUrl(c.env),
      ingestUrl: `${parsedDomain.origin}${ingestPath}`,
      statusUrl: `${parsedDomain.origin}/api/telemetry/status`,
      directoryUrl: `${requestOrigin(c)}/api/directory`,
      ownerId: resolveOwnerId(c),
      registeredAt: current?.registeredAt ?? now,
      updatedAt: now,
      lastSeen: now,
    };
    await kvPutRaw(c.env.USAGE_KV, directoryKey(nodeId), JSON.stringify(node));
    return c.json({
      status: 'success',
      applied: [action],
      node: serializeDirectoryNode(node),
    });
  }

  return c.json(
    {
      status: 'error',
      code: 'NO_ADMIN_ACTION',
      message: 'Specify action: register, update, activate, or deactivate.',
    },
    400,
  );
});

app.notFound(async (c) => {
  try {
    return await c.env.ASSETS.fetch(c.req.raw);
  } catch (error) {
    console.error('[assets] fetch failed:', error);
    return c.json({ status: 'error', code: 'NOT_FOUND', message: 'Not found.' }, 404);
  }
});

export default app;
