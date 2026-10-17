/** A loggable cause with nothing quoted from inputs: the error's name and a scrubbed message. */
export function describeError(e: unknown): string {
  if (!(e instanceof Error)) return "unknown";
  const message = e.message
    .replace(/"[^"]*"|'[^']*'|`[^`]*`/g, "…")
    .replace(/[A-Za-z0-9+/_=-]{24,}/g, "…")
    .slice(0, 200);
  return `${e.name}: ${message}`;
}
