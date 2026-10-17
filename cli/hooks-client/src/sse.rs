//! A hand-written Server-Sent Events parser (the WHATWG `text/event-stream` rules), fed raw bytes in
//! whatever chunks the network delivers.

/// One dispatched event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SseEvent {
    /// The `event:` field; `None` means the default type, `message`.
    pub event: Option<String>,
    /// The `data:` lines joined with `\n`.
    pub data: String,
    /// The `id:` field given in this event's block, if any.
    pub id: Option<String>,
}

/// What the parser produces, in stream order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SseItem {
    Event(SseEvent),
    /// A comment line (`: hb`), without the colon and one leading space.
    Comment(String),
    /// A valid `retry:` field, in milliseconds.
    Retry(u64),
}

/// A line or an event grew past the parser's limit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("an event on the stream is larger than {0} bytes")]
pub struct TooLarge(pub usize);

/// Incremental parser. Feed it with [`SseParser::push`]; it keeps partial lines between calls.
#[derive(Debug)]
pub struct SseParser {
    line: Vec<u8>,
    /// The previous chunk ended with `\r`: a `\n` at the start of the next one belongs to it.
    after_cr: bool,
    /// Whether the leading byte-order mark has been dealt with, and the bytes held while unsure.
    started: bool,
    bom: Vec<u8>,
    event: Option<String>,
    data: String,
    has_data: bool,
    id: Option<String>,
    last_event_id: Option<String>,
    max: usize,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new(DEFAULT_MAX)
    }
}

/// Lines and events up to 16 MiB: a 1 MiB body is about 1.4 MB of base64.
pub const DEFAULT_MAX: usize = 16 * 1024 * 1024;

impl SseParser {
    pub fn new(max: usize) -> Self {
        SseParser {
            line: Vec::new(),
            after_cr: false,
            started: false,
            bom: Vec::new(),
            event: None,
            data: String::new(),
            has_data: false,
            id: None,
            last_event_id: None,
            max,
        }
    }

    /// The last `id:` seen, as the spec's "last event ID buffer".
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Feed bytes; returns every item completed by them.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseItem>, TooLarge> {
        let mut out = Vec::new();
        if !self.started {
            // Strip one UTF-8 BOM at the very start of the stream, even when split across chunks.
            const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
            let mut head = std::mem::take(&mut self.bom);
            head.extend_from_slice(chunk);
            if head.len() < 3 && BOM.starts_with(&head) {
                self.bom = head;
                return Ok(out);
            }
            self.started = true;
            let rest = head.strip_prefix(&BOM[..]).unwrap_or(&head);
            self.feed(rest, &mut out)?;
            return Ok(out);
        }
        self.feed(chunk, &mut out)?;
        Ok(out)
    }

    fn feed(&mut self, bytes: &[u8], out: &mut Vec<SseItem>) -> Result<(), TooLarge> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut start = 0;
        let mut i = 0;
        if self.after_cr && bytes.first() == Some(&b'\n') {
            start = 1;
            i = 1;
        }
        self.after_cr = false;
        while i < bytes.len() {
            match bytes[i] {
                b'\n' | b'\r' => {
                    self.line.extend_from_slice(&bytes[start..i]);
                    let line = std::mem::take(&mut self.line);
                    self.process_line(&line, out)?;
                    if bytes[i] == b'\r' {
                        if i + 1 < bytes.len() {
                            if bytes[i + 1] == b'\n' {
                                i += 1;
                            }
                        } else {
                            self.after_cr = true;
                        }
                    }
                    i += 1;
                    start = i;
                }
                _ => i += 1,
            }
        }
        self.line.extend_from_slice(&bytes[start..]);
        if self.line.len() > self.max {
            self.line.clear();
            return Err(TooLarge(self.max));
        }
        Ok(())
    }

    fn process_line(&mut self, line: &[u8], out: &mut Vec<SseItem>) -> Result<(), TooLarge> {
        if line.is_empty() {
            self.dispatch(out);
            return Ok(());
        }
        let text = String::from_utf8_lossy(line);
        if let Some(comment) = text.strip_prefix(':') {
            out.push(SseItem::Comment(
                comment.strip_prefix(' ').unwrap_or(comment).to_string(),
            ));
            return Ok(());
        }
        let (field, value) = match text.find(':') {
            Some(at) => {
                let v = &text[at + 1..];
                (&text[..at], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (&text[..], ""),
        };
        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => {
                if self.data.len() + value.len() + 1 > self.max {
                    self.reset_block();
                    return Err(TooLarge(self.max));
                }
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
            "id" => {
                if !value.contains('\0') {
                    self.id = Some(value.to_string());
                    self.last_event_id = Some(value.to_string());
                }
            }
            "retry" => {
                let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                if let Some(ms) = digits.then(|| value.parse::<u64>().ok()).flatten() {
                    out.push(SseItem::Retry(ms));
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn dispatch(&mut self, out: &mut Vec<SseItem>) {
        if !self.has_data {
            // No data: nothing is dispatched, but the block's fields are cleared.
            self.reset_block();
            return;
        }
        let mut data = std::mem::take(&mut self.data);
        if data.ends_with('\n') {
            data.pop();
        }
        let event = self.event.take().filter(|e| !e.is_empty());
        out.push(SseItem::Event(SseEvent {
            event,
            data,
            id: self.id.take(),
        }));
        self.reset_block();
    }

    fn reset_block(&mut self) {
        self.event = None;
        self.data.clear();
        self.has_data = false;
        self.id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(event: Option<&str>, data: &str, id: Option<&str>) -> SseItem {
        SseItem::Event(SseEvent {
            event: event.map(str::to_string),
            data: data.to_string(),
            id: id.map(str::to_string),
        })
    }

    fn parse_all(input: &[u8]) -> Vec<SseItem> {
        SseParser::default().push(input).unwrap()
    }

    /// Feed `input` split at every possible pair of boundaries; the result never depends on them.
    fn assert_chunking_invariant(input: &[u8]) {
        let whole = parse_all(input);
        for a in 0..=input.len() {
            for b in a..=input.len() {
                let mut p = SseParser::default();
                let mut got = p.push(&input[..a]).unwrap();
                got.extend(p.push(&input[a..b]).unwrap());
                got.extend(p.push(&input[b..]).unwrap());
                assert_eq!(got, whole, "split at {a} and {b}");
            }
        }
        // And one byte at a time.
        let mut p = SseParser::default();
        let mut got = Vec::new();
        for byte in input {
            got.extend(p.push(std::slice::from_ref(byte)).unwrap());
        }
        assert_eq!(got, whole, "byte by byte");
    }

    #[test]
    fn parses_the_protocol_example() {
        let input = b"retry: 5000\n\nevent: ready\ndata: {\"after\":40}\n\nid: 41\nevent: hook\ndata: {\"seq\":41}\n\n: hb\n";
        assert_eq!(
            parse_all(input),
            vec![
                SseItem::Retry(5000),
                ev(Some("ready"), "{\"after\":40}", None),
                ev(Some("hook"), "{\"seq\":41}", Some("41")),
                SseItem::Comment("hb".into()),
            ]
        );
        assert_chunking_invariant(input);
    }

    #[test]
    fn handles_crlf_and_lone_cr() {
        let crlf = b"event: a\r\ndata: 1\r\n\r\nevent: b\rdata: 2\r\rdata: 3\n\n";
        assert_eq!(
            parse_all(crlf),
            vec![
                ev(Some("a"), "1", None),
                ev(Some("b"), "2", None),
                ev(None, "3", None)
            ]
        );
        assert_chunking_invariant(crlf);
    }

    #[test]
    fn a_crlf_split_across_chunks_is_one_line_end() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: x\r").unwrap().is_empty());
        // The \n completes the \r: it must not count as an empty line (which would dispatch).
        assert!(p.push(b"\n").unwrap().is_empty());
        assert_eq!(p.push(b"\r\n").unwrap(), vec![ev(None, "x", None)]);
    }

    #[test]
    fn joins_multi_line_data() {
        let input = b"data: first\ndata:second\ndata\ndata:  two spaces\n\n";
        assert_eq!(
            parse_all(input),
            vec![ev(None, "first\nsecond\n\n two spaces", None)]
        );
        assert_chunking_invariant(input);
    }

    #[test]
    fn comments_are_reported_and_do_not_dispatch() {
        let input = b": hb\n:\n:no space\ndata: x\n: inside\n\n";
        assert_eq!(
            parse_all(input),
            vec![
                SseItem::Comment("hb".into()),
                SseItem::Comment("".into()),
                SseItem::Comment("no space".into()),
                SseItem::Comment("inside".into()),
                ev(None, "x", None),
            ]
        );
    }

    #[test]
    fn retry_accepts_only_digits() {
        let input = b"retry: 1500\nretry: 2s\nretry: -1\nretry:\nretry:30000\n\n";
        assert_eq!(
            parse_all(input),
            vec![SseItem::Retry(1500), SseItem::Retry(30000)]
        );
        assert_chunking_invariant(input);
    }

    #[test]
    fn blocks_without_data_are_not_dispatched_but_ids_stick() {
        let mut p = SseParser::default();
        let out = p.push(b"id: 7\nevent: hook\n\ndata: x\n\n").unwrap();
        // The second block has no id of its own, and the first block's event type is cleared.
        assert_eq!(out, vec![ev(None, "x", None)]);
        assert_eq!(p.last_event_id(), Some("7"));
    }

    #[test]
    fn ids_with_nul_are_ignored() {
        let mut p = SseParser::default();
        let out = p.push(b"id: a\0b\ndata: x\n\n").unwrap();
        assert_eq!(out, vec![ev(None, "x", None)]);
        assert_eq!(p.last_event_id(), None);
    }

    #[test]
    fn unknown_fields_and_trailing_partial_events_are_ignored() {
        let mut p = SseParser::default();
        let out = p.push(b"foo: bar\ndata: done\n\ndata: unfinished").unwrap();
        assert_eq!(out, vec![ev(None, "done", None)]);
    }

    #[test]
    fn strips_one_bom_even_when_split() {
        let input = b"\xEF\xBB\xBFdata: x\n\n";
        assert_eq!(parse_all(input), vec![ev(None, "x", None)]);
        assert_chunking_invariant(input);
        // Not a BOM: a field name that happens to start with 0xEF is kept as content.
        let mut p = SseParser::default();
        assert!(p.push(b"\xEF").unwrap().is_empty());
        assert_eq!(p.push(b"\ndata: y\n\n").unwrap(), vec![ev(None, "y", None)]);
    }

    #[test]
    fn refuses_unbounded_lines() {
        let mut p = SseParser::new(16);
        assert_eq!(p.push(&[b'a'; 17]), Err(TooLarge(16)));
        let mut p = SseParser::new(16);
        assert_eq!(
            p.push(b"data: 0123456789\ndata: 0123456789\n"),
            Err(TooLarge(16))
        );
    }
}
