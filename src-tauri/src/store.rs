use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
pub type Result<T> = std::result::Result<T, String>;
pub fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
pub fn id() -> String {
    Uuid::new_v4().to_string()
}
pub fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}
pub fn write_private(path: &Path, bytes: &[u8], create_new: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}
pub fn defaults() -> Value {
    let mut data = json!({"version":2,"settings":{"reducedMotion":false,"liveNetwork":false,"language":"system"},"history":[],"audits":[],"scans":[],"rules":[],"profiles":[],"activeVpn":null,"activeScan":null,"firewallBackup":null,"automation":{},"scheduleFolder":null,"networkMonitor":null,"networkHistory":[],"quarantine":[],"killSwitch":null});
    for (key, value) in crate::automation::defaults().as_object().unwrap() {
        data["settings"][key] = value.clone();
    }
    data
}
pub const LANGUAGES: [&str; 11] = [
    "system", "pt-BR", "en", "es", "fr", "de", "ru", "zh-CN", "ja", "ar", "hi",
];
pub fn settings(value: &Value) -> Result<()> {
    let fields = value.as_object().ok_or("invalid-settings")?;
    if fields.is_empty() {
        return Err("invalid-settings".into());
    }
    for (key, val) in fields {
        match key.as_str() {
            "language" if val.as_str().is_some_and(|s| LANGUAGES.contains(&s)) => (),
            "reducedMotion" | "liveNetwork" if val.is_boolean() => (),
            _ if crate::automation::valid(key, val) => (),
            _ => return Err("invalid-settings".into()),
        }
    }
    Ok(())
}
pub fn parse(text: &str) -> Result<Value> {
    let mut value: Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())?;
    if value["version"] != 2 {
        return Err("unsupported-store-version".into());
    }
    if value["settings"].is_object() {
        for (key, default) in crate::automation::defaults().as_object().unwrap() {
            if value["settings"].get(key).is_none() {
                value["settings"][key] = default.clone();
            }
        }
    }
    for key in [
        "automation",
        "scheduleFolder",
        "networkMonitor",
        "networkHistory",
        "quarantine",
        "killSwitch",
    ] {
        if value.get(key).is_none() {
            value[key] = defaults()[key].clone();
        }
    }
    if !value["automation"].is_object()
        || !value["networkHistory"].is_array()
        || !value["quarantine"].is_array()
    {
        return Err("invalid-local-data".into());
    }
    for key in ["history", "audits", "scans", "rules", "profiles"] {
        if !value[key]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_object))
        {
            return Err("invalid-local-data".into());
        }
    }
    for key in ["activeScan", "activeVpn", "firewallBackup"] {
        if !value[key].is_null() && !value[key].is_object() {
            return Err("invalid-local-data".into());
        }
    }
    for profile in value["profiles"].as_array().unwrap() {
        let meta = &profile["meta"];
        if !profile["id"].is_string()
            || !profile["name"].is_string()
            || !meta.is_object()
            || !meta["dns"]
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string))
            || !meta["fullTunnel"].is_boolean()
            || !meta["ipv6"].is_boolean()
        {
            return Err("invalid-local-data".into());
        }
    }
    settings(&value["settings"])?;
    if !value["settings"]["reducedMotion"].is_boolean()
        || !value["settings"]["liveNetwork"].is_boolean()
        || !value["settings"]["language"].is_string()
    {
        return Err("invalid-local-data".into());
    }
    Ok(value)
}
pub struct Store {
    pub dir: PathBuf,
    pub data: Value,
    pub recovery: Option<String>,
}
impl Store {
    pub fn open(dir: PathBuf) -> Result<Self> {
        private_dir(&dir)?;
        let file = dir.join("state.json");
        let mut result = Self {
            dir,
            data: defaults(),
            recovery: None,
        };
        if file.exists() {
            match read_limited(&file, 32 * 1024 * 1024).and_then(|text| parse(&text)) {
                Ok(data) => result.data = data,
                Err(_) => {
                    let data = parse(
                        &read_limited(&file.with_extension("json.bak"), 32 * 1024 * 1024)
                            .map_err(|_| "invalid-local-data-preserved")?,
                    )?;
                    fs::copy(
                        &file,
                        result.dir.join(format!("state.corrupt-{}.json", id())),
                    )
                    .map_err(|e| e.to_string())?;
                    result.data = data;
                    result.recovery=Some("Dados locais recuperados da cópia anterior. O arquivo inválido foi preservado.".into());
                    result.save()?;
                }
            }
        }
        if !result.data["activeScan"].is_null() {
            let mut scan = result.data["activeScan"].take();
            scan["state"] = json!("interrupted");
            scan["endedAt"] = json!(now());
            if scan["summary"].is_object() {
                scan["summary"]["partial"] = json!(true);
            }
            result.data["scans"].as_array_mut().unwrap().insert(0, scan);
            result.save()?;
        }
        Ok(result)
    }
    pub fn save(&mut self) -> Result<()> {
        let bytes = fit_budget(&mut self.data, 32 * 1024 * 1024)?;
        parse(std::str::from_utf8(&bytes).unwrap())?;
        let file = self.dir.join("state.json");
        let temp = self.dir.join(format!("state-{}.tmp", id()));
        write_private(&temp, &bytes, true)?;
        if file.exists()
            && fs::read_to_string(&file)
                .ok()
                .and_then(|s| parse(&s).ok())
                .is_some()
        {
            fs::copy(&file, file.with_extension("json.bak")).map_err(|e| e.to_string())?;
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            };
            let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let to: Vec<u16> = file.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    from.as_ptr(),
                    to.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        #[cfg(not(windows))]
        fs::rename(&temp, &file).map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn push(&mut self, key: &str, value: Value, max: usize) -> Result<()> {
        let items = self.data[key].as_array_mut().ok_or("invalid-local-data")?;
        items.insert(0, value);
        items.truncate(max);
        self.save()
    }
    pub fn event(&mut self, kind: &str, title: &str, detail: Value, status: &str) -> Result<()> {
        self.push(
            "history",
            json!({"id":id(),"at":now(),"type":kind,"title":title,"detail":detail,"status":status}),
            500,
        )
    }
}
pub fn fit_budget(data: &mut Value, max: usize) -> Result<Vec<u8>> {
    loop {
        let bytes = serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?;
        if bytes.len() <= max {
            return Ok(bytes);
        }
        let mut removed = false;
        for key in ["scans", "audits", "history"] {
            if let Some(items) = data[key].as_array_mut() {
                if items.len() > 1 {
                    items.pop();
                    removed = true;
                    break;
                }
            }
        }
        if !removed {
            return Err("local-data-too-large".into());
        }
    }
}
pub fn read_limited(path: &Path, max: u64) -> Result<String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > max {
        return Err("file-too-large".into());
    }
    let mut result = String::new();
    file.take(max + 1)
        .read_to_string(&mut result)
        .map_err(|e| e.to_string())?;
    if result.len() as u64 > max {
        return Err("file-too-large".into());
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_are_strict() {
        for v in [
            json!({"language":"../../x"}),
            json!({"liveNetwork":"true"}),
            json!({"x":true}),
            Value::Null,
        ] {
            assert!(settings(&v).is_err());
        }
        assert!(settings(&json!({"language":"ar","reducedMotion":true})).is_ok());
    }
    #[test]
    fn recovery_preserves_corruption() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Store::open(d.path().into()).unwrap();
        s.event("test", "keep", json!(""), "success").unwrap();
        s.data["settings"]["language"] = json!("de");
        s.save().unwrap();
        fs::write(d.path().join("state.json"), "broken").unwrap();
        let recovered = Store::open(d.path().into()).unwrap();
        assert!(recovered.recovery.is_some());
        assert_eq!(recovered.data["history"][0]["title"], "keep");
        assert!(fs::read_dir(d.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("state.corrupt")));
    }
    #[test]
    fn malformed_runtime_state_recovers_without_panicking() {
        for bad in [json!(true), json!("running"), json!([])] {
            let d = tempfile::tempdir().unwrap();
            let mut s = Store::open(d.path().into()).unwrap();
            s.event("test", "keep", json!(""), "success").unwrap();
            s.save().unwrap();
            let mut corrupt = defaults();
            corrupt["activeScan"] = bad;
            let original = serde_json::to_string(&corrupt).unwrap();
            fs::write(d.path().join("state.json"), &original).unwrap();
            let recovered = Store::open(d.path().into()).unwrap();
            assert!(recovered.recovery.is_some());
            assert_eq!(recovered.data["history"][0]["title"], "keep");
            let preserved = fs::read_dir(d.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("state.corrupt")
                })
                .unwrap();
            assert_eq!(fs::read_to_string(preserved).unwrap(), original);
        }
    }
    #[test]
    fn malformed_collections_and_profile_metadata_are_rejected() {
        for field in ["history", "audits", "scans", "rules", "profiles"] {
            let mut data = defaults();
            data[field] = json!([null]);
            assert!(parse(&data.to_string()).is_err(), "{field}");
        }
        for field in ["activeVpn", "firewallBackup"] {
            let mut data = defaults();
            data[field] = json!(false);
            assert!(parse(&data.to_string()).is_err(), "{field}");
        }
        let mut data = defaults();
        data["profiles"] = json!([{"id":"profile","name":"VPN","meta":{"dns":null,"fullTunnel":true,"ipv6":true}}]);
        assert!(parse(&data.to_string()).is_err());
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn budget_keeps_latest_result() {
        let mut data = defaults();
        data["scans"] = json!([{"id":"latest","summary":{"infected":1,"threats":[{"name":"test"}]}},{"id":"old","lines":["x".repeat(3000)]}]);
        let bytes = fit_budget(&mut data, 1500).unwrap();
        assert!(bytes.len() <= 1500);
        assert_eq!(data["scans"][0]["id"], "latest");
        assert_eq!(data["scans"][0]["summary"]["infected"], 1);
        assert_eq!(data["scans"].as_array().unwrap().len(), 1);
    }
}
