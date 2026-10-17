//! `00hooks service install|uninstall|status`: run `00hooks run` at login.

use std::path::PathBuf;

use hooks_client::StateDir;
use hooks_runner::config::Automations;
use hooks_runner::service::{self, Spec};

use crate::automate::automations_path;
use crate::ctx::{CliResult, Failure, open_state, sentence};

fn spec(file: Option<PathBuf>) -> CliResult<Spec> {
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| Failure::new(format!("Can't find this program's own path: {e}.")))?;
    let state_dir = StateDir::default_path().map_err(|e| Failure::new(sentence(&e.to_string())))?;
    let automations = automations_path(file)?;
    let automations = if automations.is_absolute() {
        automations
    } else {
        std::env::current_dir()
            .map(|d| d.join(&automations))
            .unwrap_or(automations)
    };
    Ok(Spec {
        exe,
        state_dir,
        keystore: std::env::var("HOOKS_KEYSTORE")
            .ok()
            .filter(|v| !v.is_empty()),
        automations,
        path: std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into()),
    })
}

/// `00hooks service install [--print]`.
pub fn install(file: Option<PathBuf>, print: bool) -> CliResult {
    let spec = spec(file)?;
    if print {
        print!("{}", service::contents(&spec));
        return Ok(());
    }
    let state = open_state()?;
    if state.load_config().ok().flatten().is_none() {
        return Err(Failure::new(
            "This computer isn't logged in. Run `00hooks login --relay <URL>` first; the service runs as this login.",
        ));
    }
    if let Err(ps) = Automations::load(&spec.automations) {
        return Err(Failure::new(format!(
            "{} has problems; fix them first (`00hooks automations check`). The first: line {}: {}",
            spec.automations.display(),
            ps[0].line,
            ps[0].message
        )));
    }
    for line in service::install(&spec).map_err(|e| Failure::new(sentence(&e.to_string())))? {
        println!("{line}");
    }
    Ok(())
}

pub fn uninstall() -> CliResult {
    for line in service::uninstall().map_err(|e| Failure::new(sentence(&e.to_string())))? {
        println!("{line}");
    }
    Ok(())
}

pub fn status() -> CliResult {
    for line in service::status().map_err(|e| Failure::new(sentence(&e.to_string())))? {
        println!("{line}");
    }
    Ok(())
}
