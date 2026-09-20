import type {FrameOptions, FrameTransport, SelectionOptions, ServerExpectation} from './index.js';

export declare class BunNativeConnector {
  supports(scope: string, transport: string): boolean;
  connect(endpoint: string, options?: FrameOptions): BunFrameTransport;
  runtimeEndpoint(): never;
  selectRuntime(options?: SelectionOptions): Promise<Readonly<ServerExpectation>>;
}

export declare class BunFrameTransport implements FrameTransport {
  constructor(endpoint: string, options?: FrameOptions);
  readonly endpoint: string;
  readonly server: null;
  readonly timeout: number;
  readonly deadline: number | null;
  readonly cancellation: AbortSignal | null;
  readonly maxFrame: number;
  readonly sessions: boolean;
  callScope(): BunFrameTransport;
  withWaiting(options?: {deadline?: number | null; cancellation?: AbortSignal | null}): BunFrameTransport;
  exchangeFrame(frame: Uint8Array): Promise<Uint8Array>;
  writeFrame(frame: Uint8Array): Promise<void>;
}
