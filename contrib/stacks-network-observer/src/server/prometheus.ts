export interface PrometheusSample {
  metric: Record<string, string>;
  value: [number, string];
}

interface PrometheusResponse {
  status: 'success' | 'error';
  data?: {resultType: string; result: PrometheusSample[]};
  error?: string;
}

/** A deliberately narrow Prometheus client: callers select one reviewed query. */
export class PrometheusClient {
  constructor(
    private readonly endpoint: string,
    private readonly timeoutMs = 2_000,
  ) {}

  async query(expression: string): Promise<PrometheusSample[]> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const url = new URL('/api/v1/query', this.endpoint);
      url.searchParams.set('query', expression);
      const response = await fetch(url, {signal: controller.signal});
      if (!response.ok) throw new Error(`Prometheus returned HTTP ${response.status}`);
      const decoded = await response.json() as PrometheusResponse;
      if (decoded.status !== 'success' || !decoded.data || decoded.data.resultType !== 'vector') {
        throw new Error(decoded.error ?? 'Prometheus returned an invalid vector response');
      }
      return decoded.data.result;
    } finally {
      clearTimeout(timeout);
    }
  }
}
