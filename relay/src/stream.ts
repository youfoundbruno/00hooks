// `GET /v1/stream` and `POST /v1/ack` (PROTOCOL §6–§7).

import { accountStub, type Caller } from "./auth.ts";
import { SseBridge, type BridgeOptions } from "./bridge.ts";
import { HttpError, invalid, json, parseJsonObject, unauthorized } from "./http.ts";

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
  const lastEventIdHeader = request.headers.get("Last-Event-ID");
  let lastEventId = 0;
  if (lastEventIdHeader !== null && lastEventIdHeader.trim() !== "") {
    if (!/^\d{1,15}$/.test(lastEventIdHeader.trim())) {
      throw new HttpError(invalid("Last-Event-ID", "Last-Event-ID must be an event's seq."));
    }
    lastEventId = Number(lastEventIdHeader.trim());
  }
  const params = new URLSearchParams({ account: caller.accountId, device: caller.deviceId, lastEventId: String(lastEventId) });
  const upstream = await accountStub(env, caller.accountId).fetch(`https://account/stream?${params}`, {
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
