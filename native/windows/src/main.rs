// SPDX-License-Identifier: GPL-3.0-only
#[cfg_attr(not(windows), allow(dead_code))]
mod model;
#[cfg(windows)]
mod platform;

fn main() {
    #[cfg(windows)]
    let result = platform::run();
    #[cfg(not(windows))]
    let result: Result<(), String> =
        Err("This native adapter requires Windows; no native operations were performed".into());

    if let Err(error) = result {
        println!(
            "{}",
            serde_json::json!({"schemaVersion": 1, "ok": false, "platform": "windows", "installed": false, "active": false, "enforcementActive": false, "authenticated": false, "policyInitialized": false, "monitoring": false, "error": error})
        );
        std::process::exit(1);
    }
}
