/** Byte framing only; the caller supplies authenticated/owned I/O and retires on errors. */
export declare function readFrameFrom(read: (size: number) => Promise<Uint8Array> | Uint8Array, limit?: number): Promise<Uint8Array | null>;
export declare function writeFrameTo(write: (bytes: Uint8Array) => Promise<number> | number, frame: Uint8Array, limit?: number): Promise<void>;
export declare function framesFrom(input: AsyncIterable<Uint8Array>, limit?: number): AsyncGenerator<Uint8Array>;
