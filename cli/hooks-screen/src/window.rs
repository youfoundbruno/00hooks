//! Time windows (PLAN §6a, "Rules"; PROTOCOL §4b): a condition that holds when an item arrived
//! within some hours of some days, in a time zone.
//!
//! `{"on": "time", "from": "22:00", "to": "06:00", "days"?: [5], "tz"?: "Europe/Lisbon", "not"?: true}`
//! holds when the item's received time, read as a wall clock in `tz` (UTC when absent), falls on
//! one of `days` (0 is Sunday; every day when absent) within `[from, to)`. A window whose `from` is
//! after its `to` runs past midnight, and the day it is on is the day it started: Friday's
//! 22:00 to 06:00 holds from Friday 22:00 to Saturday 06:00. `to` may be `24:00`, the end of the day.
//!
//! The time is the item's `received_at`: for a webhook, when the relay received it (signed by the
//! relay with the event), not this machine's clock, so an event read late, or after a restart, is
//! judged by when it arrived, and the edge, which judges the same delivery at that same instant,
//! comes to the same answer. Zones come from the IANA database bundled with `jiff`, never the
//! system's, so every machine reads them alike; an unknown zone doesn't compile.

use jiff::Timestamp;
use jiff::tz::TimeZone;

/// The most different zones the relay takes in one hook's screen (each is an `Intl` formatter
/// there); a rule that would name more stays home.
pub const MAX_EDGE_ZONES: usize = 8;

/// A time window, ready to test.
#[derive(Debug, Clone)]
pub struct Window {
    /// Minutes since midnight: `from` in 0..1440, `to` in 0..=1440, never equal. A `to` of 00:00
    /// runs past midnight to nothing, so "22:00 to 00:00" is the day's last two hours.
    from: u16,
    to: u16,
    /// Bit `d` set for each day `d` (0 is Sunday) it is on.
    days: u8,
    tz: TimeZone,
}

/// `HH:MM`, two digits each; `24:00` only where `end` allows it.
fn minutes(s: &str, end: bool) -> Option<u16> {
    let b = s.as_bytes();
    if b.len() != 5 || b[2] != b':' || ![0, 1, 3, 4].iter().all(|&i| b[i].is_ascii_digit()) {
        return None;
    }
    let h = u16::from(b[0] - b'0') * 10 + u16::from(b[1] - b'0');
    let m = u16::from(b[3] - b'0') * 10 + u16::from(b[4] - b'0');
    let t = h * 60 + m;
    (m < 60 && (h < 24 || (end && t == 1440))).then_some(t)
}

/// Whether a zone's name is spelled as the IANA names are: letters first, then letters, digits,
/// `_`, `+` and `-`, in parts joined by `/`; at most 64 characters. (So no offsets like `+01:00`,
/// and no dots.)
pub fn zone_name_ok(tz: &str) -> bool {
    tz.len() <= 64
        && tz.starts_with(|c: char| c.is_ascii_alphabetic())
        && tz.split('/').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-'))
        })
}

/// The zone a window reads, by its IANA name; `None` when it isn't one.
pub fn zone(tz: &str) -> Option<TimeZone> {
    // `Factory` is the database's "no local time"; the relay's `Intl` doesn't take it.
    if !zone_name_ok(tz) || tz.eq_ignore_ascii_case("factory") {
        return None;
    }
    // `Etc/Unknown` reads as a zone with no name (and no offset); it isn't one.
    TimeZone::get(tz).ok().filter(|z| z.iana_name().is_some())
}

impl Window {
    /// Check a window; the error is one sentence and starts with the field it is about.
    pub fn new(
        from: &str,
        to: &str,
        days: Option<&[u8]>,
        tz: Option<&str>,
    ) -> Result<Window, String> {
        let from_m = minutes(from, false).ok_or("from is a time of day, HH:MM, 00:00 to 23:59")?;
        let to_m = minutes(to, true).ok_or("to is a time of day, HH:MM, 00:00 to 24:00")?;
        if to_m == from_m {
            return Err("to is a different time from from".into());
        }
        let days = match days {
            None => 0x7f,
            Some(list) => {
                let mut bits = 0u8;
                for &d in list {
                    if d > 6 || bits & (1 << d) != 0 {
                        return Err("days lists each day once, 0 (Sunday) to 6".into());
                    }
                    bits |= 1 << d;
                }
                if bits == 0 {
                    return Err("days lists each day once, 0 (Sunday) to 6".into());
                }
                bits
            }
        };
        let tz = match tz {
            None => TimeZone::UTC,
            Some(name) => {
                zone(name).ok_or_else(|| format!("tz: {name} isn't a known time zone"))?
            }
        };
        Ok(Window {
            from: from_m,
            to: to_m,
            days,
            tz,
        })
    }

    /// Whether an item received at `at` (Unix milliseconds) is within the window.
    pub fn holds(&self, at: i64) -> bool {
        let Ok(t) = Timestamp::from_millisecond(at) else {
            return false;
        };
        let local = t.to_zoned(self.tz.clone());
        let day = local.weekday().to_sunday_zero_offset() as u8;
        let m = u16::from(local.hour() as u8) * 60 + u16::from(local.minute() as u8);
        let on = |d: u8| self.days & (1 << d) != 0;
        if self.from < self.to {
            on(day) && self.from <= m && m < self.to
        } else {
            // Past midnight: the evening part is today's window, the morning part yesterday's.
            (m >= self.from && on(day)) || (m < self.to && on((day + 6) % 7))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_of_day_are_two_digits_each() {
        assert_eq!(minutes("00:00", false), Some(0));
        assert_eq!(minutes("23:59", false), Some(1439));
        assert_eq!(minutes("24:00", false), None);
        assert_eq!(minutes("24:00", true), Some(1440));
        assert_eq!(minutes("24:01", true), None);
        assert_eq!(minutes("9:00", false), None);
        assert_eq!(minutes("09:60", false), None);
        assert_eq!(minutes("09-00", false), None);
        assert_eq!(minutes("０9:00", false), None);
    }

    #[test]
    fn zone_names_are_iana_spellings() {
        assert!(zone("Europe/Lisbon").is_some());
        assert!(zone("America/Argentina/Buenos_Aires").is_some());
        assert!(zone("Etc/GMT+5").is_some());
        assert!(zone("UTC").is_some());
        assert!(zone("Mars/Olympus").is_none());
        assert!(zone("+01:00").is_none());
        assert!(zone("../zoneinfo/UTC").is_none());
        assert!(zone("Europe//Lisbon").is_none());
        assert!(zone("").is_none());
        assert!(zone("Etc/Unknown").is_none());
        assert!(zone("Factory").is_none());
    }

    #[test]
    fn an_end_of_midnight_is_the_end_of_the_day() {
        let at = |s: &str| s.parse::<Timestamp>().unwrap().as_millisecond();
        let w = Window::new("22:00", "00:00", Some(&[4]), None).unwrap();
        assert!(w.holds(at("2026-10-22T23:00:00Z"))); // a Thursday
        assert!(!w.holds(at("2026-10-23T00:30:00Z")));
        assert!(!w.holds(at("2026-10-23T23:00:00Z")));
        assert!(Window::new("00:00", "00:00", None, None).is_err());
        assert!(Window::new("00:00", "24:00", None, None).is_ok());
    }
}
