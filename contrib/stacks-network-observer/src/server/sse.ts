/** Minimal writable surface used by a bounded server-sent-event stream. */
export interface EventStreamWritable {
  readonly destroyed?: boolean;
  readonly writableEnded?: boolean;
  write(message: string): boolean;
  once(event: 'drain', listener: () => void): unknown;
  end(): unknown;
}

/**
 * A backpressure-aware SSE writer that retains only the latest pending event.
 *
 * Node returns `false` from `write` after accepting data into its buffer. That
 * is a request to wait for `drain`, not a delivery failure. While blocked, a
 * snapshot stream needs only the newest state, so intermediate states are
 * coalesced into one bounded pending message.
 */
export class LatestEventStream {
  private blocked = false;
  private closed = false;
  private pending: string | null = null;

  constructor(private readonly writable: EventStreamWritable) {}

  push(message: string): boolean {
    if (this.closed || this.writable.destroyed || this.writable.writableEnded) return false;
    if (this.blocked) {
      this.pending = message;
      return true;
    }
    this.write(message);
    return true;
  }

  detach(): void {
    this.closed = true;
    this.pending = null;
  }

  end(): void {
    if (this.closed) return;
    this.detach();
    this.writable.end();
  }

  private write(message: string): void {
    if (this.writable.write(message)) return;
    this.blocked = true;
    this.writable.once('drain', () => this.flush());
  }

  private flush(): void {
    if (this.closed) return;
    this.blocked = false;
    const pending = this.pending;
    this.pending = null;
    if (pending !== null) this.write(pending);
  }
}
