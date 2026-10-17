// `GET /v1/stream` and `POST /v1/ack` (PROTOCOL §6–§7).

import { accountStub, type Caller } from "./auth.ts";
import { SseBridge, type BridgeOptions } from "./bridge.ts";
import { HttpError, error, invalid, json, parseJsonObject, unauthorized } from "./http.ts";
import { PROTOCOLS, STREAM_PROTOCOL } from "./version.ts";

/** The header a client names the stream protocol it speaks with (PROTOCOL §0). */
export const HEADER_PROTOCOL = "X-00h-Protocol";

export const STREAM_HEADERS = {
  "Content-Type": "text/event-stream",
  "Cache-Control": "no-cache, no-transform",
  "X-Accel-Buffering": "no",
};

export async function openStream(
  request: Request,
  env: Env,
  caller: Caller,
  bridgeOptions?: BridgeOptions,
): Promise<Response> {
  // Every event is sealed in protocol 2: a client that can't open envelopes would get only gaps, so
  // it is told to update instead.
  const asked = request.headers.get(HEADER_PROTOCOL)?.trim();
  if (asked !== String(STREAM_PROTOCOL)) {
    throw new HttpError(
      error(400, "invalid", `This relay streams protocol ${STREAM_PROTOCOL}; send ${HEADER_PROTOCOL}: ${STREAM_PROTOCOL}, or update the client.`, {
        field: HEADER_PROTOCOL,
        protocols: PROTOCOLS,
      }),
    );
  }
  const lastEventIdHeader = request.headers.get("Last-Event-ID");
  let lastEventId = 0;
  if (lastEventIdHeader !== null && lastEventIdHeader.trim() !== "") {
    if (!/^\d{1,15}$/.test(lastEventIdHeader.trim())) {
      throw new HttpError(invalid("Last-Event-ID", "Last-Event-ID must be an event's seq."));
    }
    lastEventId = Number(lastEventIdHeader.trim());
  }
  const stub = accountStub(env, caller.accountId);
  if (new URL(request.url).searchParams.get("probe") === "1") {
    // A probe answers `ready` and ends, without replacing the device's live stream (for doctor).
    const r = await stub.probe(caller.deviceId, lastEventId);
    if (!r) throw new HttpError(unauthorized());
    const ready = { accountId: caller.accountId, deviceId: caller.deviceId, ...r, protocol: STREAM_PROTOCOL };
    const text = `retry: 5000\n\nevent: ready\ndata: ${JSON.stringify(ready)}\n\nevent: closed\ndata: ${JSON.stringify({ code: 1000, reason: "probe" })}\n\n`;
    return new Response(text, { status: 200, headers: STREAM_HEADERS });
  }
  const params = new URLSearchParams({ account: caller.accountId, device: caller.deviceId, lastEventId: String(lastEventId) });
  const upstream = await stub.fetch(`https://account/stream?${params}`, {
    headers: { Upgrade: "websocket" },
  });
  const ws = upstream.webSocket;
  if (upstream.status !== 101 || !ws) throw new HttpError(unauthorized());
  ws.accept();
  const bridge = new SseBridge(
    {
      send: (m) => ws.send(m),
      close: (code, reason) => ws.close(code, reason),
    },
    bridgeOptions,
  );
  ws.addEventListener("message", (e) => {
    if (typeof e.data === "string") bridge.onUpstreamMessage(e.data);
  });
  ws.addEventListener("close", (e) => bridge.onUpstreamClose(e.code));
  ws.addEventListener("error", () => bridge.onUpstreamClose(1006));
  return new Response(bridge.readable, { status: 200, headers: STREAM_HEADERS });
}

export async function ack(env: Env, caller: Caller, body: Uint8Array): Promise<Response> {
  const input = parseJsonObject(body);
  const through = input.through;
  if (typeof through !== "number" || !Number.isSafeInteger(through) || through < 0) {
    throw new HttpError(invalid("through", "through must be an event's seq."));
  }
  const acked = await accountStub(env, caller.accountId).ack(caller.deviceId, through);
  return json({ acked });
}
