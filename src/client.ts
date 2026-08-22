import { preparePaymentHeader, selectPaymentRequirements, signPaymentHeader } from 'x402/client';
import type { Network, PaymentRequirements } from 'x402/types';
import type { Hex, LocalAccount } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

// ---------------------------------------------------------------------------
// Response types (mirror worker JSON contracts)
// ---------------------------------------------------------------------------

export interface TollbaseStatus {
  status: 'success';
  agentId: string;
  usageCount: number;
  freeTierLimit: number;
  remainingFreeBlips: number;
  paymentRequired: boolean;
  pricePerBlip: string;
  network: string;
}

export interface TelemetrySuccess {
  status: 'success';
  blipId: string;
  agentId: string;
  event: string;
  billingMode: 'free' | 'paid';
  persisted: boolean;
  usageCount: number;
  freeTierLimit: number;
  ingestedAt: string;
  idempotentReplay?: boolean;
}

export interface PaymentRequiredBody {
  status: 'payment_required';
  code: string;
  message: string;
  agentId?: string;
  usageCount?: number;
  freeTierLimit?: number;
  x402Version: number;
  accepts: PaymentRequirements[];
}

export interface ApiErrorBody {
  status: 'error';
  code: string;
  message: string;
}

export type SendTelemetryResult =
  | { ok: true; data: TelemetrySuccess; paidViaRetry?: boolean }
  | { ok: false; paymentRequired: true; challenge: PaymentRequiredBody }
  | { ok: false; paymentRequired: false; error: ApiErrorBody; status: number };

export class PaymentRequiredError extends Error {
  readonly status = 402;
  readonly challenge: PaymentRequiredBody;

  constructor(challenge: PaymentRequiredBody) {
    super(challenge.message);
    this.name = 'PaymentRequiredError';
    this.challenge = challenge;
  }
}

export class TollbaseApiError extends Error {
  readonly status: number;
  readonly body: ApiErrorBody;

  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.name = 'TollbaseApiError';
    this.status = status;
    this.body = body;
  }
}

export class PaymentSigningError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'PaymentSigningError';
    if (cause instanceof Error) {
      this.cause = cause;
    }
  }
}

/** viem LocalAccount or any object x402 can sign EIP-3009 typed data with. */
export type TollbaseSigner = LocalAccount;

export interface SendTelemetryOptions {
  /** Stable key sent as `X-Idempotency-Key` so retries reuse the same ingest. */
  idempotencyKey?: string;
  /** Optional blip timestamp used by the worker when deriving a fallback key. */
  timestamp?: string;
}

export interface TollbaseClientOptions {
  fetch?: typeof fetch;
  /** Hex-encoded EVM private key used to sign EIP-3009 USDC authorizations. */
  privateKey?: Hex;
  /** Pre-constructed viem account/signer. Takes precedence over `privateKey`. */
  signer?: TollbaseSigner;
  /** Preferred x402 network when selecting from `accepts` (default: `base`). */
  network?: Network;
  /** Automatically sign and retry when the worker returns HTTP 402 (default: true when a signer is configured). */
  autoRetryPayment?: boolean;
}

export interface TollbaseClientConfig extends TollbaseClientOptions {
  endpoint: string;
  agentId: string;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class TollbaseClient {
  private readonly endpoint: string;
  private readonly agentId: string;
  private readonly fetchImpl: typeof fetch;
  private readonly signer: TollbaseSigner | null;
  private readonly paymentNetwork: Network;
  private readonly autoRetryPayment: boolean;

  constructor(config: TollbaseClientConfig);
  constructor(endpoint: string, agentId: string, options?: TollbaseClientOptions);
  constructor(
    endpointOrConfig: string | TollbaseClientConfig,
    agentId?: string,
    options: TollbaseClientOptions = {},
  ) {
    const config: TollbaseClientConfig =
      typeof endpointOrConfig === 'string'
        ? { endpoint: endpointOrConfig, agentId: agentId ?? '', ...options }
        : endpointOrConfig;

    this.endpoint = config.endpoint.replace(/\/+$/, '');
    this.agentId = config.agentId;
    this.fetchImpl = config.fetch ?? fetch;
    this.paymentNetwork = config.network ?? 'base';
    this.signer = config.signer ?? (config.privateKey ? privateKeyToAccount(config.privateKey) : null);
    this.autoRetryPayment = config.autoRetryPayment ?? this.signer !== null;
  }

  private agentHeaders(extra?: HeadersInit): Headers {
    const headers = new Headers(extra);
    headers.set('X-Agent-Id', this.agentId);
    return headers;
  }

  private async parseJson<T>(response: Response): Promise<T> {
    try {
      return (await response.json()) as T;
    } catch {
      throw new TollbaseApiError(response.status, {
        status: 'error',
        code: 'INVALID_JSON',
        message: 'Worker returned a non-JSON response.',
      });
    }
  }

  private async postTelemetryRequest(
    event: string,
    payload: Record<string, unknown>,
    options: { paymentHeader?: string; idempotencyKey?: string; timestamp?: string } = {},
  ): Promise<Response> {
    const headers = this.agentHeaders({ 'Content-Type': 'application/json' });
    if (options.paymentHeader) {
      headers.set('X-PAYMENT', options.paymentHeader);
    }
    if (options.idempotencyKey) {
      headers.set('X-Idempotency-Key', options.idempotencyKey);
    }

    const body: Record<string, unknown> = { event, payload };
    if (options.timestamp) {
      body.timestamp = options.timestamp;
    }

    return this.fetchImpl(`${this.endpoint}/api/telemetry`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  }

  /**
   * 32-byte EIP-3009 nonce from `crypto.getRandomValues`. Refuses to sign if
   * a CSPRNG is not available (never falls back to Math.random).
   */
  private createSecureEip3009Nonce(): Hex {
    const cryptoObj = globalThis.crypto;
    if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
      throw new PaymentSigningError(
        'Cannot generate EIP-3009 nonce: crypto.getRandomValues is unavailable.',
      );
    }
    const bytes = cryptoObj.getRandomValues(new Uint8Array(32));
    let hex = '0x';
    for (let i = 0; i < bytes.length; i += 1) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex as Hex;
  }

  /**
   * Select payment requirements from a 402 challenge and sign an EIP-3009
   * TransferWithAuthorization payload for the Base (or configured) network.
   */
  private async signPaymentChallenge(challenge: PaymentRequiredBody): Promise<string> {
    if (!this.signer) {
      throw new PaymentSigningError(
        'Cannot sign x402 payment: configure `privateKey` or `signer` on TollbaseClient.',
      );
    }

    if (!challenge.accepts?.length) {
      throw new PaymentSigningError('402 response did not include any payment requirements.');
    }

    const requirement = selectPaymentRequirements(
      challenge.accepts,
      this.paymentNetwork,
      'exact',
    );

    try {
      const unsigned = preparePaymentHeader(this.signer.address, challenge.x402Version, requirement);
      unsigned.payload.authorization.nonce = this.createSecureEip3009Nonce();
      return await signPaymentHeader(this.signer, requirement, unsigned);
    } catch (error) {
      if (error instanceof PaymentSigningError) {
        throw error;
      }
      throw new PaymentSigningError(
        error instanceof Error ? error.message : 'Failed to sign x402 payment header',
        error,
      );
    }
  }

  /** Fetch current allowance and billing metrics for this agent. */
  async getStatus(): Promise<TollbaseStatus> {
    const response = await this.fetchImpl(`${this.endpoint}/api/telemetry/status`, {
      method: 'GET',
      headers: this.agentHeaders(),
    });

    if (!response.ok) {
      const body = await this.parseJson<ApiErrorBody>(response);
      throw new TollbaseApiError(response.status, body);
    }

    return this.parseJson<TollbaseStatus>(response);
  }

  /**
   * POST a telemetry blip. When a signer is configured and `autoRetryPayment`
   * is enabled, HTTP 402 responses trigger automatic EIP-3009 signing and a
   * single retry with the `X-PAYMENT` header to complete settlement.
   */
  async sendTelemetry(
    event: string,
    payload: Record<string, unknown> = {},
    options: SendTelemetryOptions = {},
  ): Promise<SendTelemetryResult> {
    const requestOptions = {
      idempotencyKey: options.idempotencyKey,
      timestamp: options.timestamp,
    };
    let response = await this.postTelemetryRequest(event, payload, requestOptions);

    if (response.status === 402 && this.signer && this.autoRetryPayment) {
      const challenge = await this.parseJson<PaymentRequiredBody>(response);

      try {
        const paymentHeader = await this.signPaymentChallenge(challenge);
        response = await this.postTelemetryRequest(event, payload, {
          ...requestOptions,
          paymentHeader,
        });
      } catch (error) {
        if (error instanceof PaymentSigningError) {
          return {
            ok: false,
            paymentRequired: false,
            status: 402,
            error: {
              status: 'error',
              code: 'PAYMENT_SIGNING_FAILED',
              message: error.message,
            },
          };
        }
        throw error;
      }

      if (response.status === 402) {
        const retryChallenge = await this.parseJson<PaymentRequiredBody>(response);
        return { ok: false, paymentRequired: true, challenge: retryChallenge };
      }

      if (!response.ok) {
        const error = await this.parseJson<ApiErrorBody>(response);
        return { ok: false, paymentRequired: false, error, status: response.status };
      }

      const data = await this.parseJson<TelemetrySuccess>(response);
      return { ok: true, data, paidViaRetry: true };
    }

    if (response.status === 402) {
      const challenge = await this.parseJson<PaymentRequiredBody>(response);
      return { ok: false, paymentRequired: true, challenge };
    }

    if (!response.ok) {
      const error = await this.parseJson<ApiErrorBody>(response);
      return { ok: false, paymentRequired: false, error, status: response.status };
    }

    const data = await this.parseJson<TelemetrySuccess>(response);
    return { ok: true, data };
  }

  /**
   * Convenience wrapper that throws {@link PaymentRequiredError} on 402 when
   * auto-retry is disabled or no signer is configured.
   */
  async sendTelemetryOrThrow(
    event: string,
    payload: Record<string, unknown> = {},
    options: SendTelemetryOptions = {},
  ): Promise<TelemetrySuccess> {
    const result = await this.sendTelemetry(event, payload, options);

    if (result.ok) {
      return result.data;
    }

    if (result.paymentRequired) {
      throw new PaymentRequiredError(result.challenge);
    }

    throw new TollbaseApiError(result.status, result.error);
  }
}

export function isPaymentRequiredError(error: unknown): error is PaymentRequiredError {
  return error instanceof PaymentRequiredError;
}
