// The edge's patterns (PROTOCOL §4b): a small regular-expression subset, parsed here and run by a
// Pike VM (a Thompson NFA simulated with state sets), so the time to match is linear in what it
// reads whatever the pattern: there is no backtracking to blow up. The harness checks the same
// subset (`cli/hooks-screen/src/fields.rs`, `edge_pattern_weight`) and runs it on the `regex`
// crate, whose semantics this follows: Unicode `\w`, `\d`, `\s` and `\b`; `.` is anything but a
// line feed; `^` and `$` are the start and end of the text; `(?i)` folds case as Unicode's simple
// case folding does. `fixtures/screen.v1.json` holds both to the same verdicts.
//
// The subset:
//
//   pattern := alt                                   1 to 200 characters; may start with (?i)
//   alt     := concat ("|" concat)*                  an empty branch matches the empty text
//   concat  := (atom [quant ["?"]])*                 assertions take no quantifier; no stacking
//   quant   := * | + | ? | {n} | {n,} | {n,m}        0 <= n <= m <= 1000, digits only
//   atom    := a character (not one of \ . + * ? ( ) | [ ] { } ^ $) | . | ^ | $ | escape | class
//            | ( alt ) | (?: alt ) | (?i: alt )       groups nest at most 8 deep
//   escape  := \d \D \w \W \s \S \b \B \n \t \r \f \v | \ and any ASCII punctuation but < >
//   class   := [ [^] item+ ]                           no nesting, no && ~~ or --; - only first
//                                                      or last; ranges between single characters
//
// Its weight (the NFA's size, near enough) is at most 250: a character, class or assertion
// weighs 1, a sequence the sum, an alternation the sum plus one per `|`, a bounded repeat
// `x{n,m}` weight(x)·max(m,1) and an open one `x{n,}` weight(x)·(n+1).

export const MAX_PATTERN = 200;
export const MAX_REPEAT = 1000;
export const MAX_WEIGHT = 250;
export const MAX_GROUP_DEPTH = 8;

export class PatternError extends Error {}

type Named = "d" | "D" | "w" | "W" | "s" | "S";

type Node =
  | { k: "empty" }
  | { k: "lit"; cp: number; ci: boolean }
  | { k: "dot" }
  | { k: "class"; neg: boolean; ranges: [number, number][]; named: Named[]; ci: boolean }
  | { k: "assert"; a: "^" | "$" | "b" | "B" }
  | { k: "cat"; xs: Node[] }
  | { k: "alt"; xs: Node[] }
  | { k: "rep"; x: Node; min: number; max: number | null };

const META = new Set([..."\\.+*?()|[]{}^$"]);
const ESCAPED_CHAR: Record<string, number> = { n: 10, t: 9, r: 13, f: 12, v: 11 };
const isPunct = (c: string) => /^[!-/:-@[-`{-~]$/.test(c) && c !== "<" && c !== ">";

class Parser {
  private pos = 0;
  private readonly cs: string[];
  constructor(cs: string[]) {
    this.cs = cs;
  }

  private peek(o = 0): string | undefined {
    return this.cs[this.pos + o];
  }

  private fail(why: string): never {
    throw new PatternError(why);
  }

  parse(): Node {
    let ci = false;
    if (this.cs.slice(0, 4).join("") === "(?i)") {
      ci = true;
      this.pos = 4;
    }
    const node = this.alt(0, ci);
    if (this.pos < this.cs.length) this.fail("an unmatched )");
    return node;
  }

  private alt(depth: number, ci: boolean): Node {
    const xs = [this.cat(depth, ci)];
    while (this.peek() === "|") {
      this.pos++;
      xs.push(this.cat(depth, ci));
    }
    return xs.length === 1 ? xs[0]! : { k: "alt", xs };
  }

  private cat(depth: number, ci: boolean): Node {
    const xs: Node[] = [];
    for (;;) {
      const c = this.peek();
      if (c === undefined || c === "|" || c === ")") break;
      const atom = this.atom(depth, ci);
      const q = this.quant();
      if (q) {
        if (atom.k === "assert") this.fail("an assertion can't repeat");
        if (this.peek() === "?") this.pos++; // lazy: the same for whether it matches
        if (["*", "+", "?", "{"].includes(this.peek() ?? "")) this.fail("a repeat can't repeat");
        xs.push({ k: "rep", x: atom, min: q.min, max: q.max });
      } else xs.push(atom);
    }
    return xs.length === 0 ? { k: "empty" } : xs.length === 1 ? xs[0]! : { k: "cat", xs };
  }

  private quant(): { min: number; max: number | null } | null {
    const c = this.peek();
    if (c === "*") return this.pos++, { min: 0, max: null };
    if (c === "+") return this.pos++, { min: 1, max: null };
    if (c === "?") return this.pos++, { min: 0, max: 1 };
    if (c !== "{") return null;
    this.pos++;
    const min = this.number();
    if (this.peek() === "}") return this.pos++, { min, max: min };
    if (this.peek() !== ",") this.fail("a repeat is {n}, {n,} or {n,m}");
    this.pos++;
    if (this.peek() === "}") return this.pos++, { min, max: null };
    const max = this.number();
    if (this.peek() !== "}") this.fail("a repeat is {n}, {n,} or {n,m}");
    this.pos++;
    if (min > max) this.fail("a repeat's {n,m} has n above m");
    return { min, max };
  }

  private number(): number {
    let s = "";
    while (/^[0-9]$/.test(this.peek() ?? "") && s.length < 5) s += this.cs[this.pos++];
    if (s === "" || /^[0-9]$/.test(this.peek() ?? "")) this.fail("a repeat is {n}, {n,} or {n,m}");
    const n = Number(s);
    if (n > MAX_REPEAT) this.fail(`a repeat counts to at most ${MAX_REPEAT}`);
    return n;
  }

  private atom(depth: number, ci: boolean): Node {
    const c = this.cs[this.pos]!;
    switch (c) {
      case "(": {
        this.pos++;
        let inner = ci;
        if (this.peek() === "?") {
          const flag = this.cs.slice(this.pos, this.pos + 3).join("");
          if (this.peek(1) === ":") this.pos += 2;
          else if (flag === "?i:") {
            this.pos += 3;
            inner = true;
          } else this.fail("the only groups are ( ), (?: ) and (?i: ), and (?i) only at the start");
        }
        if (depth + 1 > MAX_GROUP_DEPTH) this.fail(`groups nest at most ${MAX_GROUP_DEPTH} deep`);
        const node = this.alt(depth + 1, inner);
        if (this.peek() !== ")") this.fail("an unclosed (");
        this.pos++;
        return node;
      }
      case ".":
        this.pos++;
        return { k: "dot" };
      case "^":
      case "$":
        this.pos++;
        return { k: "assert", a: c };
      case "[":
        return this.cls(ci);
      case "\\": {
        const e = this.peek(1);
        this.pos += 2;
        if (e === undefined) this.fail("a pattern can't end in \\");
        if (e === "b" || e === "B") return { k: "assert", a: e };
        if ("dDwWsS".includes(e)) return { k: "class", neg: false, ranges: [], named: [e as Named], ci: false };
        if (e in ESCAPED_CHAR) return { k: "lit", cp: ESCAPED_CHAR[e]!, ci };
        if (isPunct(e)) return { k: "lit", cp: e.codePointAt(0)!, ci };
        return this.fail(`\\${e} isn't in the edge's subset`);
      }
      default:
        if (META.has(c)) this.fail(c === "*" || c === "+" || c === "?" || c === "{" ? "a repeat needs something to repeat" : `${c} needs a \\ before it`);
        this.pos++;
        return { k: "lit", cp: c.codePointAt(0)!, ci };
    }
  }

  /** One character in a class: a literal, an escaped one, or a named class (when `named`). */
  private single(): number | Named {
    const c = this.cs[this.pos]!;
    if (c !== "\\") {
      this.pos++;
      return c.codePointAt(0)!;
    }
    const e = this.peek(1);
    this.pos += 2;
    if (e === undefined) return this.fail("an unclosed [");
    if ("dDwWsS".includes(e)) return e as Named;
    if (e in ESCAPED_CHAR) return ESCAPED_CHAR[e]!;
    if (isPunct(e)) return e.codePointAt(0)!;
    return this.fail(`\\${e} isn't in the edge's subset inside [ ]`);
  }

  private cls(ci: boolean): Node {
    this.pos++;
    const neg = this.peek() === "^";
    if (neg) this.pos++;
    const ranges: [number, number][] = [];
    const named: Named[] = [];
    let items = 0;
    for (;;) {
      const c = this.peek();
      if (c === undefined) this.fail("an unclosed [");
      if (c === "]") {
        if (items === 0) this.fail("a class needs something in it (write \\] for a ])");
        this.pos++;
        break;
      }
      if (c === "[") this.fail("classes don't nest (write \\[ for a [)");
      if ((c === "&" && this.peek(1) === "&") || (c === "~" && this.peek(1) === "~")) this.fail(`${c}${c} isn't in the edge's subset`);
      if (c === "-" && items > 0 && this.peek(1) !== "]") this.fail("a - in a class goes first or last (or write \\-)");
      const lo = c === "-" ? (this.pos++, 45) : this.single();
      items++;
      if (typeof lo === "string") {
        if (this.peek() === "-" && this.peek(1) !== "]" && this.peek(1) !== undefined) this.fail("a range goes between two characters");
        named.push(lo);
        continue;
      }
      if (c !== "-" && this.peek() === "-" && this.peek(1) !== "]" && this.peek(1) !== undefined) {
        this.pos++;
        const hi = this.single();
        if (typeof hi === "string") this.fail("a range goes between two characters");
        if (hi < lo) this.fail("a range goes from low to high");
        ranges.push([lo, hi]);
      } else ranges.push([lo, lo]);
    }
    return { k: "class", neg, ranges, named, ci };
  }
}

function weigh(n: Node): number {
  const cap = (x: number) => Math.min(x, MAX_WEIGHT + 1);
  switch (n.k) {
    case "empty":
      return 0;
    case "lit":
    case "dot":
    case "class":
    case "assert":
      return 1;
    case "cat":
      return cap(n.xs.reduce((s, x) => s + weigh(x), 0));
    case "alt":
      return cap(n.xs.reduce((s, x) => s + weigh(x), 0) + n.xs.length - 1);
    case "rep":
      return cap(weigh(n.x) * (n.max === null ? n.min + 1 : Math.max(n.max, 1)));
  }
}

function parse(pattern: string): { node: Node; weight: number } {
  if (typeof pattern !== "string") throw new PatternError("a pattern is text");
  const cs = [...pattern];
  if (cs.length === 0) throw new PatternError("the pattern is empty");
  if (cs.length > MAX_PATTERN) throw new PatternError(`a pattern is at most ${MAX_PATTERN} characters`);
  const node = new Parser(cs).parse();
  const weight = weigh(node);
  if (weight > MAX_WEIGHT) throw new PatternError(`the pattern is too large once its repeats are counted (at most ${MAX_WEIGHT})`);
  return { node, weight };
}

/** The pattern's weight when it is in the edge's subset; throws `PatternError` when it isn't. */
export function patternWeight(pattern: string): number {
  return parse(pattern).weight;
}

// ── characters ──────────────────────────────────────────────────────────────────────────────────

/** A test of one code point, remembered (ASCII up front, the rest as met, boundedly). */
class CharTest {
  private readonly ascii = new Int8Array(128).fill(-1);
  private readonly seen = new Map<number, boolean>();
  private readonly test: (cp: number) => boolean;
  constructor(test: (cp: number) => boolean) {
    this.test = test;
  }
  has(cp: number): boolean {
    if (cp < 128) {
      let a = this.ascii[cp]!;
      if (a < 0) this.ascii[cp] = a = this.test(cp) ? 1 : 0;
      return a === 1;
    }
    let v = this.seen.get(cp);
    if (v === undefined) {
      if (this.seen.size >= 4096) this.seen.clear();
      this.seen.set(cp, (v = this.test(cp)));
    }
    return v;
  }
}

const one = (re: RegExp) => (cp: number) => re.test(String.fromCodePoint(cp));
const WORD_CLASS = "\\p{Alphabetic}\\p{M}\\p{Pc}\\p{Nd}\\p{Join_Control}";
const NAMED_TESTS: Record<"d" | "w" | "s", CharTest> = {
  d: new CharTest(one(/^\p{Nd}$/u)),
  w: new CharTest(one(new RegExp(`^[${WORD_CLASS}]$`, "u"))),
  s: new CharTest(one(/^\p{White_Space}$/u)),
};
const isWord = (cp: number) => NAMED_TESTS.w.has(cp);

function namedHas(n: Named, cp: number): boolean {
  const lower = n.toLowerCase() as "d" | "w" | "s";
  return NAMED_TESTS[lower].has(cp) !== (n !== lower);
}

const NAMED_SOURCE: Record<Named, string> = {
  d: "\\p{Nd}",
  D: "\\P{Nd}",
  s: "\\p{White_Space}",
  S: "\\P{White_Space}",
  w: `[${WORD_CLASS}]`,
  W: `[^${WORD_CLASS}]`,
};
const cpSource = (cp: number) => `\\u{${cp.toString(16)}}`;

/** A case-folding test, as the `regex` crate folds: JavaScript's `v` and `i` flags fold by Unicode's simple case folding too. */
function foldedTest(neg: boolean, ranges: [number, number][], named: Named[]): (cp: number) => boolean {
  const items = ranges.map(([lo, hi]) => (lo === hi ? cpSource(lo) : `${cpSource(lo)}-${cpSource(hi)}`)).concat(named.map((n) => NAMED_SOURCE[n]));
  return one(new RegExp(`^[${neg ? "^" : ""}${items.join("")}]$`, "vi"));
}

function charTest(n: Extract<Node, { k: "lit" | "dot" | "class" }>): CharTest {
  if (n.k === "dot") return new CharTest((cp) => cp !== 10);
  if (n.k === "lit") return new CharTest(n.ci ? foldedTest(false, [[n.cp, n.cp]], []) : (cp) => cp === n.cp);
  if (n.ci) return new CharTest(foldedTest(n.neg, n.ranges, n.named));
  const { neg, ranges, named } = n;
  return new CharTest((cp) => (ranges.some(([lo, hi]) => cp >= lo && cp <= hi) || named.some((x) => namedHas(x, cp))) !== neg);
}

// ── the program and its VM ──────────────────────────────────────────────────────────────────────

const CHAR = 0;
const SPLIT = 1;
const JMP = 2;
const ASSERT = 3;
const MATCH = 4;
const A_START = 0;
const A_END = 1;
const A_WORD = 2;
const A_NOT_WORD = 3;

/** Work counted against a delivery's budget; `step` throws once it is spent. */
export interface Steps {
  step(n: number): void;
}

export class CompiledPattern {
  private readonly op: number[] = [];
  private readonly x: number[] = [];
  private readonly y: number[] = [];
  private readonly tests: (CharTest | null)[] = [];
  private cur!: Int32Array;
  private next!: Int32Array;
  private mark!: Int32Array;
  private gen = 0;
  private stack!: Int32Array;

  readonly source: string;
  readonly weight: number;

  constructor(source: string, weight: number, node: Node) {
    this.source = source;
    this.weight = weight;
    this.emit(node);
    this.push(MATCH, 0, 0, null);
    const n = this.op.length;
    this.cur = new Int32Array(n);
    this.next = new Int32Array(n);
    this.mark = new Int32Array(n);
    this.stack = new Int32Array(2 * n + 2);
  }

  get size(): number {
    return this.op.length;
  }

  private push(op: number, x: number, y: number, t: CharTest | null): number {
    this.op.push(op);
    this.x.push(x);
    this.y.push(y);
    this.tests.push(t);
    return this.op.length - 1;
  }

  private emit(n: Node): void {
    switch (n.k) {
      case "empty":
        return;
      case "lit":
      case "dot":
      case "class":
        this.push(CHAR, 0, 0, charTest(n));
        return;
      case "assert":
        this.push(ASSERT, n.a === "^" ? A_START : n.a === "$" ? A_END : n.a === "b" ? A_WORD : A_NOT_WORD, 0, null);
        return;
      case "cat":
        for (const x of n.xs) this.emit(x);
        return;
      case "alt": {
        const jumps: number[] = [];
        for (let i = 0; i < n.xs.length; i++) {
          if (i < n.xs.length - 1) {
            const split = this.push(SPLIT, 0, 0, null);
            this.x[split] = split + 1;
            this.emit(n.xs[i]!);
            jumps.push(this.push(JMP, 0, 0, null));
            this.y[split] = this.op.length;
          } else this.emit(n.xs[i]!);
        }
        for (const j of jumps) this.x[j] = this.op.length;
        return;
      }
      case "rep": {
        for (let i = 0; i < n.min; i++) this.emit(n.x);
        if (n.max === null) {
          // x*: L: split(L+1, out); x; jmp L
          const split = this.push(SPLIT, 0, 0, null);
          this.x[split] = split + 1;
          this.emit(n.x);
          this.push(JMP, split, 0, null);
          this.y[split] = this.op.length;
        } else {
          // (max − min) optional copies: each split(next copy, out)
          const splits: number[] = [];
          for (let i = n.min; i < n.max; i++) {
            const split = this.push(SPLIT, 0, 0, null);
            this.x[split] = split + 1;
            splits.push(split);
            this.emit(n.x);
          }
          for (const s of splits) this.y[s] = this.op.length;
        }
        return;
      }
    }
  }

  /** Adds `pc` and what it reaches without reading, at `at` (between code points); true on a match. */
  private add(list: Int32Array, len: number[], pc: number, cps: Int32Array, at: number, steps: Steps): boolean {
    const stack = this.stack;
    let sp = 0;
    stack[sp++] = pc;
    let visited = 0;
    let matched = false;
    while (sp > 0) {
      const p = stack[--sp]!;
      if (this.mark[p] === this.gen) continue;
      this.mark[p] = this.gen;
      visited++;
      switch (this.op[p]) {
        case CHAR:
          list[len[0]!++] = p;
          break;
        case MATCH:
          matched = true;
          sp = 0;
          break;
        case JMP:
          stack[sp++] = this.x[p]!;
          break;
        case SPLIT:
          stack[sp++] = this.y[p]!;
          stack[sp++] = this.x[p]!;
          break;
        case ASSERT: {
          const a = this.x[p];
          let ok: boolean;
          if (a === A_START) ok = at === 0;
          else if (a === A_END) ok = at === cps.length;
          else {
            const before = at > 0 && isWord(cps[at - 1]!);
            const after = at < cps.length && isWord(cps[at]!);
            ok = (before !== after) === (a === A_WORD);
          }
          if (ok) stack[sp++] = p + 1;
          break;
        }
      }
    }
    steps.step(visited);
    return matched;
  }

  /** Whether the pattern matches anywhere in `cps` (code points). Linear: |cps| · size steps at most. */
  test(cps: Int32Array, steps: Steps): boolean {
    if (this.gen > 1_000_000_000) {
      this.mark.fill(0);
      this.gen = 0;
    }
    let cur = this.cur;
    let next = this.next;
    const curLen = [0];
    const nextLen = [0];
    this.gen++;
    for (let at = 0; ; at++) {
      // A thread starts at every position: the pattern isn't anchored unless it says ^.
      if (this.add(cur, curLen, 0, cps, at, steps)) return true;
      if (at === cps.length) return false;
      const cp = cps[at]!;
      this.gen++;
      nextLen[0] = 0;
      const n = curLen[0]!;
      steps.step(n);
      for (let i = 0; i < n; i++) {
        const p = cur[i]!;
        if (this.tests[p]!.has(cp) && this.add(next, nextLen, p + 1, cps, at + 1, steps)) return true;
      }
      [cur, next] = [next, cur];
      curLen[0] = nextLen[0]!;
    }
  }
}

/** The first `max` code points of a value, as a pattern reads them. */
export function codePoints(value: string, max: number): Int32Array {
  const out = new Int32Array(Math.min(value.length, max));
  let n = 0;
  for (let i = 0; i < value.length && n < max; ) {
    const cp = value.codePointAt(i)!;
    out[n++] = cp;
    i += cp > 0xffff ? 2 : 1;
  }
  return out.subarray(0, n);
}

/** Compiles a pattern of the edge's subset; throws `PatternError` when it isn't one. */
export function compilePattern(pattern: string): CompiledPattern {
  const { node, weight } = parse(pattern);
  return new CompiledPattern(pattern, weight, node);
}
