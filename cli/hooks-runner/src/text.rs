//! Text from outside, made harmless to show.

/// Bidirectional formatting characters and the Unicode line and paragraph separators: invisible,
/// and able to reorder or break what a terminal or a notification shows.
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

/// Remove control characters (C0, C1, DEL) and bidirectional formatting; tabs and newlines become
/// spaces.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' | '\t' | '\r' => out.push(' '),
            c if c.is_control() || is_bidi_or_separator(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// The first `max` characters, with `…` when cut.
pub fn cut(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_controls() {
        assert_eq!(sanitize("a\u{1b}[2Jb\u{9b}\u{202e}c\nd"), "a[2Jbc d");
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(cut("abc", 4), "abc");
    }
}
