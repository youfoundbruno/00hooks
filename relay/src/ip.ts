// The client address a limit is keyed on. IPv4 addresses count one by one; IPv6 by /64, the block a
// single subscriber usually holds (one host can use any of 2^64 addresses in it).

/** The key for `CF-Connecting-IP`: the IPv4 address, or the IPv6 /64 prefix; "unknown" without one. */
export function clientKey(request: Request): string {
  return ipKey(request.headers.get("CF-Connecting-IP"));
}

export function ipKey(ip: string | null): string {
  const raw = (ip ?? "").trim();
  if (!raw) return "unknown";
  if (!raw.includes(":")) return raw;
  const groups = expandIpv6(raw);
  if (!groups) return raw.toLowerCase();
  // IPv4-mapped (::ffff:a.b.c.d) is an IPv4 client.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return [groups[6]! >> 8, groups[6]! & 255, groups[7]! >> 8, groups[7]! & 255].join(".");
  }
  return `${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(":")}::/64`;
}

/** The eight 16-bit groups of an IPv6 address, or null when it doesn't parse. */
export function expandIpv6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  // A trailing dotted IPv4 part is two groups.
  const dotted = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (dotted) {
    const b = dotted.slice(1).map(Number);
    if (b.some((x) => x > 255)) return null;
    s = `${s.slice(0, dotted.index)}${((b[0]! << 8) | b[1]!).toString(16)}:${((b[2]! << 8) | b[3]!).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string) => (part === "" ? [] : part.split(":"));
  const head = parse(halves[0]!);
  const tail = halves.length === 2 ? parse(halves[1]!) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  const out: number[] = [];
  for (const g of all) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}
