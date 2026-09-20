// Declarations for index.js, the Node-API connector over the shared IPC C ABI.

export declare const Status: Readonly<{
  Ok: 0;
  Timeout: 1;
  Disconnected: 2;
  IoError: 3;
  InvalidArgument: 4;
  NoMemory: 5;
  InternalError: 6;
  Cancelled: 7;
  Untrusted: 8;
  ProofUnavailable: 9;
}>;
export type Status = (typeof Status)[keyof typeof Status];

export declare class FrameError extends Error {
  constructor(status: Status, message: string, transferred?: number);
  status: Status;
  transferred: number;
}

export interface ServerExpectation {
  principalKind: 1 | 2;
  principal: string;
  program: string;
}

export interface FrameOptions {
  timeout?: number;
  deadline?: number | null;
  cancellation?: AbortSignal | null;
  maxFrame?: number;
  server?: ServerExpectation | null;
  /** Keep verified connections for later calls (FRAMING.md "Sessions"). */
  sessions?: boolean;
}

/** The installed per-user runtime's resolver endpoint. */
export declare function runtimeEndpoint(): string;

export interface SelectionOptions {
  timeout?: number;
  deadline?: number | null;
  cancellation?: AbortSignal | null;
}

/**
 * The installed runtime's identity from the shared native selector. Connects to nothing.
 * Rejects with FrameError: Status.Untrusted for no or an ambiguous installation,
 * Status.ProofUnavailable where the platform lacks the facilities.
 */
export declare function selectRuntime(options?: SelectionOptions): Promise<Readonly<ServerExpectation>>;

export declare class NativeConnector {
  supports(scope: string, transport: string): boolean;
  connect(endpoint: string, options?: FrameOptions): FrameTransport;
  runtimeEndpoint(): string;
  selectRuntime(options?: SelectionOptions): Promise<Readonly<ServerExpectation>>;
}

export declare class FrameTransport {
  constructor(endpoint: string, options?: FrameOptions);
  readonly server: Readonly<ServerExpectation> | null;
  readonly endpoint: string;
  readonly timeout: number;
  readonly deadline: number | null;
  readonly cancellation: AbortSignal | null;
  readonly maxFrame: number;
  readonly sessions: boolean;
  callScope(): FrameTransport;
  withWaiting(options?: { deadline?: number | null; cancellation?: AbortSignal | null }): FrameTransport;
  exchangeFrame(frame: Uint8Array): Promise<Uint8Array>;
  writeFrame(frame: Uint8Array): Promise<void>;
}
