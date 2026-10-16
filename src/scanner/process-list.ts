/**
 * The output limit for reading the process listing (`ps aux`).
 *
 * `execSync` keeps 1 MiB of a command's output by default and throws ENOBUFS
 * past it. A host running many processes, or processes with long command
 * lines, prints more than that from `ps aux`, and the listing then read as a
 * failure: `detect` counted the process surface as unread although `ps` ran
 * (#1123). Every `ps aux` read passes this as `maxBuffer`.
 */
export const PROCESS_LIST_MAX_BYTES = 256 * 1024 * 1024;
