// Declarations for platform.js, the platform-package table the connectors resolve against.

export declare const platformLibraries: Readonly<Record<string, string>>;
export declare const addonFile: string;
export declare function platformIdentity(): string;
export declare function platformPackage(identity: string): string;
export declare function platformLibrary(identity: string): string | null;
export declare function platformFile(
  resolve: (specifier: string) => string,
  identity: string,
  file: string,
): string | null;
