//! Per-automation state that must survive a restart: recent run times (the rate limit) and
//! failures in a row (the circuit breaker). Saved atomically in `automations-state.json`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::config::RateLimit;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoState {
    /// When it ran, within the longest rate window (a day).
    #[serde(default)]
    pub runs: Vec<i64>,
    /// Failed runs in a row.
    #[serde(default)]
    pub failures: u32,
    /// Paused by the circuit breaker until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<i64>,
    /// When we last said it hit its rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limited_told_at: Option<i64>,
}

/// Whether an automation may run now.
#[derive(Debug, Clone, PartialEq)]
pub enum Admit {
    Run,
    /// Over its rate limit; `tell` is true the first time in a window.
    RateLimited {
        tell: bool,
    },
    /// Paused by the circuit breaker.
    Paused {
        until: i64,
    },
}

/// What recording a result changed.
#[derive(Debug, Clone, PartialEq)]
pub enum Breaker {
    Unchanged,
    /// It just paused, after this many failures in a row.
    Paused {
        failures: u32,
        until: i64,
    },
    /// It ran fine after being paused.
    Recovered,
}

#[derive(Debug)]
pub struct States {
    path: PathBuf,
    pub map: BTreeMap<String, AutoState>,
}

const DAY_MS: i64 = 86_400_000;

impl States {
    pub fn open(dir: &Path) -> Result<States> {
        let path = dir.join("automations-state.json");
        let map = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(States { path, map })
    }

    /// Re-read the file: `00hooks automations resume` may have changed it.
    pub fn reload(&mut self) -> Result<()> {
        let fresh = States::open(self.path.parent().unwrap_or(Path::new(".")))?;
        self.map = fresh.map;
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.map).expect("json");
        hooks_client::fsutil::write_atomic(&self.path, &bytes, true)
            .map_err(crate::Error::from_client)
    }

    /// May `name` run now? Counts the run when it may.
    pub fn admit(&mut self, name: &str, rate: Option<RateLimit>, now: i64) -> Admit {
        let s = self.map.entry(name.to_string()).or_default();
        s.runs.retain(|t| now - *t < DAY_MS);
        if let Some(until) = s.paused_until
            && now < until
        {
            return Admit::Paused { until };
        }
        if let Some(r) = rate {
            let window = r.per.as_millis() as i64;
            let recent = s.runs.iter().filter(|t| now - **t < window).count();
            if recent >= r.max as usize {
                let tell = s.limited_told_at.is_none_or(|t| now - t >= window);
                if tell {
                    s.limited_told_at = Some(now);
                }
                return Admit::RateLimited { tell };
            }
        }
        s.runs.push(now);
        Admit::Run
    }

    /// Record how a run went.
    pub fn record(
        &mut self,
        name: &str,
        ok: bool,
        pause_after: u32,
        pause_for: Duration,
        now: i64,
    ) -> Breaker {
        let s = self.map.entry(name.to_string()).or_default();
        if ok {
            let was_paused = s.paused_until.is_some();
            s.failures = 0;
            s.paused_until = None;
            return if was_paused {
                Breaker::Recovered
            } else {
                Breaker::Unchanged
            };
        }
        s.failures += 1;
        if pause_after > 0 && s.failures >= pause_after {
            let until = now + pause_for.as_millis() as i64;
            s.paused_until = Some(until);
            return Breaker::Paused {
                failures: s.failures,
                until,
            };
        }
        Breaker::Unchanged
    }

    /// Lift a pause and forget the failures.
    pub fn resume(&mut self, name: &str) -> bool {
        match self.map.get_mut(name) {
            Some(s) if s.paused_until.is_some() || s.failures > 0 => {
                s.paused_until = None;
                s.failures = 0;
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_dir;

    #[test]
    fn the_rate_limit_counts_within_its_window() {
        let dir = temp_dir("state-rate");
        let mut s = States::open(&dir).unwrap();
        let rate = Some(RateLimit {
            max: 3,
            per: Duration::from_secs(3600),
        });
        let t0 = 1_000_000_000;
        for i in 0..3 {
            assert_eq!(s.admit("a", rate, t0 + i), Admit::Run);
        }
        assert_eq!(
            s.admit("a", rate, t0 + 10),
            Admit::RateLimited { tell: true }
        );
        assert_eq!(
            s.admit("a", rate, t0 + 20),
            Admit::RateLimited { tell: false }
        );
        assert_eq!(s.admit("b", rate, t0 + 20), Admit::Run, "per automation");
        // An hour later the window has moved on.
        assert_eq!(s.admit("a", rate, t0 + 3_600_001), Admit::Run);
        assert_eq!(s.admit("a", None, t0 + 3_600_002), Admit::Run, "no limit");
        // It survives a restart.
        s.save().unwrap();
        let s2 = States::open(&dir).unwrap();
        assert_eq!(s2.map["a"].runs.len(), s.map["a"].runs.len());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_breaker_pauses_after_failures_and_recovers() {
        let dir = temp_dir("state-breaker");
        let mut s = States::open(&dir).unwrap();
        let pf = Duration::from_secs(60);
        let t0 = 1_000_000_000;
        for i in 0..2 {
            assert_eq!(s.record("a", false, 3, pf, t0 + i), Breaker::Unchanged);
        }
        assert_eq!(
            s.record("a", false, 3, pf, t0 + 2),
            Breaker::Paused {
                failures: 3,
                until: t0 + 60_002
            }
        );
        assert_eq!(
            s.admit("a", None, t0 + 100),
            Admit::Paused { until: t0 + 60_002 }
        );
        // After the pause, one trial run: failing pauses again at once.
        assert_eq!(s.admit("a", None, t0 + 60_003), Admit::Run);
        assert!(matches!(
            s.record("a", false, 3, pf, t0 + 60_004),
            Breaker::Paused { failures: 4, .. }
        ));
        assert_eq!(s.admit("a", None, t0 + 120_100), Admit::Run);
        assert_eq!(s.record("a", true, 3, pf, t0 + 120_101), Breaker::Recovered);
        assert_eq!(s.map["a"].failures, 0);
        // A manual resume lifts a pause.
        for i in 0..3 {
            s.record("b", false, 3, pf, t0 + i);
        }
        assert!(s.resume("b"));
        assert_eq!(s.admit("b", None, t0 + 10), Admit::Run);
        assert!(!s.resume("nobody"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
