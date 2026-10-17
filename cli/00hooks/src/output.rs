//! Terminal output: sanitising untrusted text, formatting, and a bounded, drain-aware writer.

use std::io::{ErrorKind, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc;

/// Bidirectional formatting characters (marks, embeddings, overrides, isolates) and the Unicode
/// line and paragraph separators: invisible, and able to reorder or break what a terminal shows.
fn is_bidi_or_separator(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Remove characters that could drive the terminal (C0 and C1 controls, DEL, bidirectional
/// formatting, line separators). `multiline` keeps `\n` and `\t`; otherwise they become spaces.
pub fn sanitize(s: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' | '\t' if multiline => out.push(c),
            '\n' | '\t' | '\r' => out.push(' '),
            c if c.is_control() => {}
            c if is_bidi_or_separator(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// One JSON line that is safe to print: serde already escapes C0 controls, and this also writes
/// DEL, C1 controls, bidirectional formatting characters and line separators as `\uXXXX` escapes.
/// The value is unchanged for any JSON reader; only what reaches the terminal differs. (Outside
/// strings, JSON is ASCII, so every such character is inside a string where an escape is valid.)
pub fn json_line<T: serde::Serialize + ?Sized>(v: &T) -> String {
    let raw = serde_json::to_string(v).unwrap_or_default();
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c == '\u{7f}' || ('\u{80}'..='\u{9f}').contains(&c) || is_bidi_or_separator(c) {
            out.push_str(&format!("\\u{:04x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `512 B`, `1.2 KB`, `3.4 MB` (powers of 1024).
pub fn size(bytes: usize) -> String {
    const K: f64 = 1024.0;
    let b = bytes as f64;
    if b < K {
        format!("{bytes} B")
    } else if b < K * K {
        format!("{:.1} KB", b / K)
    } else {
        format!("{:.1} MB", b / (K * K))
    }
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian (H. Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn split(ms: i64) -> ((i64, u32, u32), (i64, i64, i64)) {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    (civil(days), (rem / 3600, (rem % 3600) / 60, rem % 60))
}

/// `2026-10-17 09:41 UTC`.
pub fn date_time(ms: i64) -> String {
    let ((y, mo, d), (h, mi, _)) = split(ms);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02} UTC")
}

/// `09:41:05` (UTC).
pub fn clock(ms: i64) -> String {
    let (_, (h, mi, s)) = split(ms);
    format!("{h:02}:{mi:02}:{s:02}")
}

/// `in 4 s`, `in 1 min 30 s`.
pub fn duration(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.0} s", d.as_secs_f64())
    } else {
        format!("{} min {} s", ms / 60_000, (ms % 60_000) / 1000)
    }
}

/// Columns padded to their widest cell, two spaces apart.
pub fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|s| s.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    let mut out = String::new();
    for row in rows {
        let mut line = String::new();
        for (c, cell) in row.iter().enumerate() {
            if c + 1 == row.len() {
                line.push_str(cell);
            } else {
                line.push_str(cell);
                let pad = widths[c] - cell.chars().count() + 2;
                line.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Where a line goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    Out(String),
    Err(String),
}

/// A writer thread fed by a bounded queue. Sending waits when the queue is full, so a slow reader
/// of stdout slows the stream down (and the relay's backpressure takes over) instead of memory
/// growing. Both streams go through the same queue so their lines stay in order.
pub struct Output {
    tx: mpsc::Sender<Line>,
    thread: std::thread::JoinHandle<()>,
    broken: Arc<AtomicBool>,
    warned: bool,
}

impl Output {
    pub fn spawn(capacity: usize) -> Self {
        Self::spawn_with(capacity, std::io::stdout(), std::io::stderr())
    }

    pub fn spawn_with<O, E>(capacity: usize, mut out: O, mut err: E) -> Self
    where
        O: Write + Send + 'static,
        E: Write + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel::<Line>(capacity);
        let broken = Arc::new(AtomicBool::new(false));
        let flag = broken.clone();
        let thread = std::thread::spawn(move || {
            while let Some(line) = rx.blocking_recv() {
                let r = match &line {
                    Line::Out(s) => writeln!(out, "{s}").and_then(|_| out.flush()),
                    Line::Err(s) => writeln!(err, "{s}").and_then(|_| err.flush()),
                };
                // Whoever reads our stdout went away (`| head`): stop quietly.
                if let Err(e) = r
                    && (matches!(line, Line::Out(_)) || e.kind() == ErrorKind::BrokenPipe)
                {
                    flag.store(true, Ordering::SeqCst);
                    return;
                }
            }
        });
        Output {
            tx,
            thread,
            broken,
            warned: false,
        }
    }

    /// Queue a line, waiting while the queue is full. `false` once stdout has gone away.
    pub async fn send(&mut self, line: Line) -> bool {
        if self.broken.load(Ordering::SeqCst) {
            return false;
        }
        match self.tx.try_send(line) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
            Err(mpsc::error::TrySendError::Full(line)) => {
                if !self.warned {
                    self.warned = true;
                    eprintln!(
                        "Output is falling behind; reading from the relay pauses until it catches up."
                    );
                }
                self.tx.send(line).await.is_ok()
            }
        }
    }

    pub async fn err(&mut self, s: impl Into<String>) -> bool {
        self.send(Line::Err(s.into())).await
    }

    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::SeqCst)
    }

    /// Write out everything queued, then stop the writer.
    pub async fn finish(self) {
        drop(self.tx);
        let thread = self.thread;
        let _ = tokio::task::spawn_blocking(move || thread.join()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn sanitize_strips_terminal_controls() {
        let evil = "ok\u{1b}[31mred\u{7}\u{9b}2J\u{202e}txt\r\nnext\tcol";
        assert_eq!(sanitize(evil, true), "ok[31mred2Jtxt \nnext\tcol");
        assert_eq!(sanitize(evil, false), "ok[31mred2Jtxt  next col");
        assert_eq!(sanitize("plain é ✓", false), "plain é ✓");
        assert_eq!(
            sanitize("a\u{2066}b\u{2028}c\u{061c}d\u{7f}e", false),
            "abcde"
        );
    }

    #[test]
    fn json_lines_escape_what_serde_leaves_raw() {
        let v = serde_json::json!({
            "t": "c1\u{9b}2J del\u{7f} rlo\u{202e}x lsep\u{2028} esc\u{1b} é ✓"
        });
        let line = json_line(&v);
        for c in ['\u{9b}', '\u{7f}', '\u{202e}', '\u{2028}', '\u{1b}'] {
            assert!(!line.contains(c), "{line:?} carries {c:?}");
        }
        assert!(line.contains("\\u009b") && line.contains("\\u202e") && line.contains("\\u007f"));
        assert!(line.contains("é ✓"), "printable text stays as it is");
        // Same value for a JSON reader.
        let back: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn formats_sizes_and_times() {
        assert_eq!(size(512), "512 B");
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(3 * 1024 * 1024), "3.0 MB");
        assert_eq!(date_time(0), "1970-01-01 00:00 UTC");
        assert_eq!(date_time(1792233600000), "2026-10-17 10:40 UTC");
        assert_eq!(clock(1792233600000 + 5_000), "10:40:05");
        assert_eq!(date_time(951_782_400_000), "2000-02-29 00:00 UTC");
        assert_eq!(duration(std::time::Duration::from_millis(4200)), "4 s");
        assert_eq!(duration(std::time::Duration::from_secs(90)), "1 min 30 s");
    }

    #[test]
    fn table_pads_columns() {
        let t = table(&[
            vec!["NAME".into(), "ID".into()],
            vec!["ci-long".into(), "hk_1".into()],
        ]);
        assert_eq!(t, "NAME     ID\nci-long  hk_1\n");
    }

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl Write for Shared {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn writer_keeps_order_and_drains_everything() {
        let (o, e) = (Shared::default(), Shared::default());
        let mut out = Output::spawn_with(2, o.clone(), e.clone());
        for i in 0..50 {
            assert!(out.send(Line::Out(format!("o{i}"))).await);
            assert!(out.err(format!("e{i}")).await);
        }
        out.finish().await;
        let o = String::from_utf8(o.0.lock().unwrap().clone()).unwrap();
        let expected: String = (0..50).map(|i| format!("o{i}\n")).collect();
        assert_eq!(o, expected);
        assert_eq!(e.0.lock().unwrap().len(), expected.len());
    }

    #[tokio::test]
    async fn a_closed_stdout_stops_the_writer() {
        let mut out = Output::spawn_with(1, Closed, Shared::default());
        out.send(Line::Out("first".into())).await;
        let mut gave_up = false;
        for _ in 0..100 {
            if !out.send(Line::Out("more".into())).await {
                gave_up = true;
                break;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(gave_up && out.is_broken());
        out.finish().await;
    }
}
