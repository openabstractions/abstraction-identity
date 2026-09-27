import type {FrameOptions, FrameTransport, SelectionOptions, ServerExpectation} from './index.js';

/** The shared C ABI library this connector opens, resolved before any native use. */
export declare function libraryPath(): string;

export declare class BunNativeConnector {
  supports(scope: string, transport: string): boolean;
  connect(endpoint: string, options?: FrameOptions): BunFrameTransport;
  /** The installed runtime's endpoint from the shared library; no connection. */
  runtimeEndpoint(): string;
  /** The installed runtime's identity from the shared native selector. */
  selectRuntime(options?: SelectionOptions): Promise<Readonly<ServerExpectation>>;
}

export declare class BunFrameTransport implements FrameTransport {
  constructor(endpoint: string, options?: FrameOptions);
  readonly endpoint: string;
  /** Enforced by the shared library on every call; required for XPC endpoints. */
  readonly server: Readonly<ServerExpectation> | null;
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
