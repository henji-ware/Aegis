use crate::{
    platform,
    runner::*,
    store::{self, Result},
    Core,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime},
};
#[derive(Clone)]
pub struct Snapshot {
    pub pid: u64,
    pub path: PathBuf,
    pub identity: String,
    pub size: u64,
    pub modified: SystemTime,
    pub expires: SystemTime,
}
pub fn assess(row: &Value, path: Option<&str>) -> Value {
    let mut signals = vec![];
    if row["state"] == "Listen" && !platform::loopback(row["localAddress"].as_str().unwrap_or("")) {
        signals.push("listener");
    }
    if path.is_some_and(|s| {
        regex::Regex::new(r"(?i)(?:[\\/](?:temp|tmp|downloads)[\\/]|^/dev/shm/)")
            .unwrap()
            .is_match(s)
    }) {
        signals.push("temporary");
    }
    json!({"level":if !signals.is_empty(){"review"}else if path.is_some(){"no-signals"}else{"unknown"},"signals":signals,"path":path,"signature":null,"inspected":path.is_some(),"at":store::now(),"token":null})
}
pub fn metadata(rows: &[Value]) -> HashMap<u64, (PathBuf, String)> {
    let mut data = HashMap::new();
    if cfg!(windows) {
        let values=ps_json("@(Get-Process | ForEach-Object {try{[pscustomobject]@{pid=$_.Id;path=$_.Path;started=$_.StartTime.ToUniversalTime().ToString('o')}}catch{}}) | ConvertTo-Json -Compress").unwrap_or(Value::Null);
        let items = match values {
            Value::Array(a) => a,
            Value::Object(_) => vec![values],
            _ => vec![],
        };
        for item in items {
            if let (Some(pid), Some(path), Some(started)) = (
                item["pid"].as_u64(),
                item["path"].as_str(),
                item["started"].as_str(),
            ) {
                if !path.is_empty() {
                    data.insert(pid, (PathBuf::from(path), started.into()));
                }
            }
        }
        return data;
    }
    for pid in rows
        .iter()
        .filter_map(|r| r["pid"].as_u64())
        .filter(|p| *p > 0)
        .take(350)
    {
        if data.contains_key(&pid) {
            continue;
        }
        if cfg!(target_os = "linux") {
            let exe = fs::read_link(format!("/proc/{pid}/exe"));
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
            if let (Ok(exe), Ok(stat)) = (exe, stat) {
                if let Some((_, tail)) = stat.rsplit_once(") ") {
                    if let Some(identity) = tail.split_whitespace().nth(19) {
                        if !exe.to_string_lossy().ends_with(" (deleted)") {
                            data.insert(pid, (exe, identity.into()));
                        }
                    }
                }
            }
        } else if cfg!(target_os = "macos") && data.len() < 80 {
            let out = run(
                std::path::Path::new("/usr/sbin/lsof"),
                &[
                    "-a".into(),
                    "-p".into(),
                    pid.to_string(),
                    "-d".into(),
                    "txt".into(),
                    "-Fn".into(),
                ],
            );
            let start = run(
                std::path::Path::new("/bin/ps"),
                &["-p".into(), pid.to_string(), "-o".into(), "lstart=".into()],
            );
            if let (Ok(text), Ok(start)) = (out, start) {
                if let Some(path) = text.lines().find_map(|s| s.strip_prefix("n/")) {
                    data.insert(pid, (PathBuf::from(format!("/{path}")), start));
                }
            }
        }
    }
    data
}
pub fn inspect(core: &Core) -> Result<Value> {
    let rows = platform::connections()?;
    let meta = metadata(&rows);
    let mut snapshots = core.analysis.lock().map_err(|_| "analysis-lock")?;
    snapshots.clear();
    Ok(json!(rows
        .into_iter()
        .map(|mut row| {
            let item = meta.get(&row["pid"].as_u64().unwrap_or(0));
            let path = item.map(|i| i.0.to_string_lossy().into_owned());
            let mut analysis = assess(&row, path.as_deref());
            if let Some((file, identity)) = item {
                if let (Ok(file), Ok(info)) = (file.canonicalize(), file.metadata()) {
                    if info.is_file() {
                        if let Ok(modified) = info.modified() {
                            let token = store::id();
                            snapshots.insert(
                                token.clone(),
                                Snapshot {
                                    pid: row["pid"].as_u64().unwrap_or(0),
                                    path: file,
                                    identity: identity.clone(),
                                    size: info.len(),
                                    modified,
                                    expires: SystemTime::now() + Duration::from_secs(120),
                                },
                            );
                            analysis["token"] = json!(token);
                        }
                    }
                }
            }
            row["analysis"] = analysis;
            row
        })
        .collect::<Vec<_>>()))
}
pub fn resolve(core: &Core, token: &str) -> Result<PathBuf> {
    let item = core
        .analysis
        .lock()
        .map_err(|_| "analysis-lock")?
        .get(token)
        .cloned()
        .ok_or("analysis-expired")?;
    if SystemTime::now() > item.expires {
        return Err("analysis-expired".into());
    }
    let rows = platform::connections()?
        .into_iter()
        .filter(|r| r["pid"].as_u64() == Some(item.pid))
        .collect::<Vec<_>>();
    let meta = metadata(&rows);
    let (path, identity) = meta.get(&item.pid).ok_or("process-changed")?;
    if identity != &item.identity || path.canonicalize().map_err(|e| e.to_string())? != item.path {
        return Err("process-changed".into());
    }
    let file = fs::metadata(&item.path).map_err(|e| e.to_string())?;
    if !file.is_file()
        || file.len() != item.size
        || file.modified().map_err(|e| e.to_string())? != item.modified
    {
        return Err("process-changed".into());
    }
    Ok(item.path)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_port_or_ip_is_declared_malicious() {
        let r = json!({"state":"Established","localAddress":"10.0.0.1","remoteAddress":"203.0.113.8","remotePort":4444});
        assert_eq!(assess(&r, None)["level"], "unknown");
        assert_eq!(
            assess(&r, Some("C:\\Program Files\\Browser\\browser.exe"))["level"],
            "no-signals"
        );
    }
    #[test]
    fn weak_signals_require_review_only() {
        let r = json!({"state":"Listen","localAddress":"0.0.0.0"});
        let a = assess(&r, Some("/tmp/app"));
        assert_eq!(a["level"], "review");
        assert_eq!(a["signals"].as_array().unwrap().len(), 2);
    }
}
