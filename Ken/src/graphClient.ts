/**
 * A small Microsoft Graph security client for a SOC triage agent.
 *
 * MMS 2026 Midway Edition - "Empowering SOC Teams".
 *
 * The point of this file: `baseUrl` and `getToken` are both injected, so the
 * same client talks to the mock server today and to graph.microsoft.com the
 * day a tenant exists. Nothing else in your agent needs to change.
 *
 *   // offline, no tenant
 *   const graph = new GraphSecurityClient({
 *     baseUrl: 'http://localhost:8787/v1.0',
 *     getToken: async () => 'mock',
 *   });
 *
 *   // live, backend service with a client secret
 *   const graph = new GraphSecurityClient({
 *     getToken: appOnlyTokenProvider({ tenantId, clientId, clientSecret }),
 *   });
 *
 * No dependencies: uses global fetch (Node 18+, and every browser).
 */

import type {
  GraphCollection,
  GraphErrorBody,
  HuntingQueryRequest,
  HuntingQueryResults,
  SecurityAlert,
  SecurityIncident,
} from './graph-types';

export const GRAPH_V1 = 'https://graph.microsoft.com/v1.0';

export interface GraphClientOptions {
  /** Defaults to the real Graph. Point at the mock server to work offline. */
  baseUrl?: string;
  /** Returns a bearer token. Called per request; cache inside your provider. */
  getToken: () => Promise<string>;
  /** Per-request timeout in ms. Default 30000. */
  timeoutMs?: number;
  /** Retries on 429 and 5xx. Default 3. */
  maxRetries?: number;
  fetchImpl?: typeof fetch;
}

/** A Graph error with the status and code attached, so callers can branch. */
export class GraphError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = 'GraphError';
  }

  /** True when the cause is almost certainly missing admin consent. */
  get isLikelyConsentProblem(): boolean {
    return (
      this.status === 403 ||
      this.code === 'Authorization_RequestDenied' ||
      this.code === 'AccessDenied'
    );
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class GraphSecurityClient {
  private readonly baseUrl: string;
  private readonly getToken: () => Promise<string>;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly fetchImpl: typeof fetch;

  constructor(options: GraphClientOptions) {
    this.baseUrl = (options.baseUrl ?? GRAPH_V1).replace(/\/+$/, '');
    this.getToken = options.getToken;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  // -- transport ---------------------------------------------------------

  private async request<T>(
    path: string,
    init: RequestInit = {},
    attempt = 0,
  ): Promise<T> {
    const token = await this.getToken();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          // Without this header, incident status never comes back as
          // 'awaitingAction' - Graph collapses unknown members instead.
          Prefer: 'include-unknown-enum-members',
          ...(init.body ? { 'Content-Type': 'application/json' } : {}),
          ...(init.headers ?? {}),
        },
      });
    } finally {
      clearTimeout(timer);
    }

    // 429 carries Retry-After and must be honoured; Graph throttles hard on
    // /security and a tight retry loop makes it worse.
    if ((response.status === 429 || response.status >= 500) && attempt < this.maxRetries) {
      const retryAfter = Number(response.headers.get('Retry-After'));
      const waitMs = Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : Math.min(2 ** attempt * 1000, 16_000);
      await sleep(waitMs);
      return this.request<T>(path, init, attempt + 1);
    }

    if (!response.ok) {
      const requestId = response.headers.get('request-id') ?? undefined;
      let code = String(response.status);
      let message = response.statusText;
      try {
        const body = (await response.json()) as GraphErrorBody;
        code = body.error?.code ?? code;
        message = body.error?.message ?? message;
      } catch {
        /* non-JSON error body; keep the status text */
      }
      throw new GraphError(response.status, code, message, requestId);
    }

    return (await response.json()) as T;
  }

  /** Follow @odata.nextLink until the collection is exhausted. */
  private async collect<T>(firstPath: string, maxPages = 20): Promise<T[]> {
    const out: T[] = [];
    let page = await this.request<GraphCollection<T>>(firstPath);
    out.push(...page.value);

    for (let i = 1; i < maxPages && page['@odata.nextLink']; i++) {
      // nextLink is absolute. Strip the base so the mock server works too.
      const next = page['@odata.nextLink']!.replace(this.baseUrl, '').replace(GRAPH_V1, '');
      page = await this.request<GraphCollection<T>>(next);
      out.push(...page.value);
    }
    return out;
  }

  // -- incidents ---------------------------------------------------------

  /**
   * GET /security/incidents
   *
   * Supported OData params are $count, $filter, $skip, $top and $expand.
   * There is no $select and no $orderby - sort client-side.
   *
   * $filter works on: assignedTo, classification, createdDateTime,
   * determination, lastUpdateDateTime, severity, status.
   */
  async listIncidents(options: {
    expandAlerts?: boolean;
    filter?: string;
    top?: number;
    all?: boolean;
  } = {}): Promise<SecurityIncident[]> {
    const params = new URLSearchParams();
    if (options.expandAlerts) params.set('$expand', 'alerts');
    if (options.filter) params.set('$filter', options.filter);
    if (options.top) params.set('$top', String(options.top));

    const path = `/security/incidents?${params.toString()}`;
    if (options.all) return this.collect<SecurityIncident>(path);

    const page = await this.request<GraphCollection<SecurityIncident>>(path);
    return page.value;
  }

  async getIncident(
    id: string,
    options: { expandAlerts?: boolean } = {},
  ): Promise<SecurityIncident> {
    const suffix = options.expandAlerts ? '?$expand=alerts' : '';
    return this.request<SecurityIncident>(`/security/incidents/${encodeURIComponent(id)}${suffix}`);
  }

  /**
   * The queue a triage agent should actually work: unassigned, still open.
   *
   * Note 'active', not 'new' - a fresh incident is 'active' in Graph's
   * incidentStatus enum. Filtering for 'new' silently returns nothing.
   */
  async listTriageQueue(options: { top?: number } = {}): Promise<SecurityIncident[]> {
    const incidents = await this.listIncidents({
      expandAlerts: true,
      filter: "status eq 'active'",
      top: options.top ?? 50,
    });
    // assignedTo is not reliably filterable for null, so drop assigned ones here.
    return incidents.filter((i) => !i.assignedTo);
  }

  /**
   * PATCH /security/incidents/{id}
   * Needs SecurityIncident.ReadWrite.All, which the registration script only
   * requests with -IncludeWriteBack.
   */
  async updateIncident(
    id: string,
    patch: Partial<
      Pick<
        SecurityIncident,
        'classification' | 'determination' | 'status' | 'assignedTo' | 'customTags'
      >
    >,
  ): Promise<SecurityIncident> {
    return this.request<SecurityIncident>(`/security/incidents/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    });
  }

  // -- alerts ------------------------------------------------------------

  /**
   * GET /security/alerts_v2
   *
   * $expand is NOT supported here. $filter works on assignedTo,
   * classification, determination, createdDateTime, lastUpdateDateTime,
   * severity, serviceSource and status.
   *
   * The legacy /security/alerts endpoint was retired on 15 October 2026.
   */
  async listAlerts(options: { filter?: string; top?: number; all?: boolean } = {}): Promise<SecurityAlert[]> {
    const params = new URLSearchParams();
    if (options.filter) params.set('$filter', options.filter);
    if (options.top) params.set('$top', String(options.top));

    const path = `/security/alerts_v2?${params.toString()}`;
    if (options.all) return this.collect<SecurityAlert>(path);

    const page = await this.request<GraphCollection<SecurityAlert>>(path);
    return page.value;
  }

  /** Alerts raised by Sentinel analytics rules specifically. */
  async listSentinelAlerts(top = 50): Promise<SecurityAlert[]> {
    return this.listAlerts({ filter: "serviceSource eq 'microsoftSentinel'", top });
  }

  // -- advanced hunting --------------------------------------------------

  /**
   * POST /security/runHuntingQuery
   *
   * Reaches Defender XDR tables always, and Sentinel Analytics-tier tables
   * once the workspace is onboarded to the Defender portal - but only inside
   * the Analytics retention window. Older or Lake-tier data needs the Log
   * Analytics query API instead.
   *
   * Hard limits: 30 days by default, 100,000 rows.
   */
  async runHuntingQuery(
    query: string,
    options: { timespan?: string; workspaceId?: string } = {},
  ): Promise<HuntingQueryResults> {
    const body: HuntingQueryRequest = { Query: query };
    if (options.timespan) body.Timespan = options.timespan;
    if (options.workspaceId) body.workspaceId = options.workspaceId;

    return this.request<HuntingQueryResults>('/security/runHuntingQuery', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /** Hunting results as typed row objects. Convenience over `results`. */
  async hunt<T = Record<string, unknown>>(
    query: string,
    options: { timespan?: string; workspaceId?: string } = {},
  ): Promise<T[]> {
    const { results } = await this.runHuntingQuery(query, options);
    return results as T[];
  }
}

// ---------------------------------------------------------------------------
// Token providers
// ---------------------------------------------------------------------------

/**
 * Client-credentials token provider for a BACKEND service.
 *
 * Never call this from the browser: it needs the client secret, and anything
 * the React bundle can read, so can the user. Put it behind your own API, or
 * host it in Foundry, and have the front end call that.
 *
 * App-only means there is no analyst identity on the call. Every request sees
 * everything the app can see. If you need per-analyst RBAC, sign the analyst
 * in from the SPA instead and use on-behalf-of.
 */
export function appOnlyTokenProvider(config: {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  fetchImpl?: typeof fetch;
}): () => Promise<string> {
  const doFetch = config.fetchImpl ?? globalThis.fetch;
  let cached: { token: string; expiresAt: number } | null = null;

  return async () => {
    // 60s of slack so a token never expires mid-flight.
    if (cached && Date.now() < cached.expiresAt - 60_000) return cached.token;

    const url = `https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`;
    const response = await doFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        // App-only always uses /.default, never individual scopes.
        scope: 'https://graph.microsoft.com/.default',
        grant_type: 'client_credentials',
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Token request failed (${response.status}): ${text}`);
    }

    const json = (await response.json()) as { access_token: string; expires_in: number };
    cached = {
      token: json.access_token,
      expiresAt: Date.now() + json.expires_in * 1000,
    };
    return cached.token;
  };
}

/** For the mock server, which does not check the token. */
export const mockTokenProvider = async () => 'mock-token';
