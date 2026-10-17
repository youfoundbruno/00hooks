// Responses. Every error body is `{ error, message }` (PROTOCOL §8); messages are fixed sentences
// written here, so they can never carry a secret, a signature or payload content.

export type ErrorCode =
  | "unauthorized"
  | "clock_skew"
  | "not_found"
  | "too_large"
  | "rate_limited"
  | "signature"
  | "invalid"
  | "conflict";

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

export function error(
  status: number,
  code: ErrorCode,
  message: string,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  return json({ error: code, message, ...extra }, status, headers);
}

export const notFound = () => error(404, "not_found", "Nothing is here.");
export const unauthorized = () => error(401, "unauthorized", "The request isn't signed by a known device.");
export const invalid = (field: string, message: string) => error(400, "invalid", message, { field });
export const tooLarge = () => error(413, "too_large", "The body is larger than this endpoint accepts.");

/** Thrown inside handlers to answer with a prepared response. */
export class HttpError extends Error {
  readonly response: Response;
  constructor(response: Response) {
    super("http error");
    this.response = response;
  }
}

/**
 * Reads a body, refusing it once it passes `limit` bytes: first from `Content-Length`, then while
 * streaming (a sender can lie about the length or send it chunked). Null means too large.
 */
export async function readLimited(request: Request, limit: number): Promise<Uint8Array<ArrayBuffer> | null> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > limit) return null;
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

/** Parses a JSON object body; throws an `invalid` answer otherwise. */
export function parseJsonObject(body: Uint8Array): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder().decode(body.byteLength ? body : new TextEncoder().encode("{}")));
  } catch {
    throw new HttpError(invalid("body", "The body must be a JSON object."));
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new HttpError(invalid("body", "The body must be a JSON object."));
  }
  return v as Record<string, unknown>;
}
