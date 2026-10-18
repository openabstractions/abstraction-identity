/**
 * Whether the deepest existing folder above `path`, resolved through links,
 * is `folder` or one of its descendants by filesystem identity.
 * Both arguments must be absolute and `folder` must exist. Filesystem errors
 * reject the promise; an unreadable path never counts as contained.
 */
export declare function within(path: string, folder: string): Promise<boolean>;
