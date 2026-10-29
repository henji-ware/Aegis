use crate::{
    runner::*,
    store::{self, Result},
    Core,
};
use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};
use tauri::{Emitter, Manager};
const SCAN_OUTPUT_BATCH: usize = 256;
fn drain_output_batch(
    receiver: &std::sync::mpsc::Receiver<String>,
    cancelled: &AtomicBool,
    mut accept: impl FnMut(&str),
) {
    for line in receiver.try_iter().take(SCAN_OUTPUT_BATCH) {
        accept(&line);
        if cancelled.load(Ordering::SeqCst) {
            break;
        }
    }
}
fn quick_targets(folders: impl IntoIterator<Item = Option<PathBuf>>) -> Vec<PathBuf> {
    let mut targets = vec![];
    let mut seen = HashSet::new();
    for folder in folders.into_iter().flatten() {
        if folder.is_absolute() && folder.is_dir() {
            let identity = folder.canonicalize().unwrap_or_else(|_| folder.clone());
            if seen.insert(identity) {
                targets.push(folder);
            }
        }
    }
    targets
}
pub fn signatures(dir: &Path) -> Value {
    let mut files = vec![];
    for name in ["daily.cvd", "daily.cld", "main.cvd", "main.cld"] {
        let file = dir.join(name);
        if let Ok(mut handle) = fs::File::open(&file) {
            let mut bytes = [0; 512];
            if let Ok(n) = handle.read(&mut bytes) {
                let text = String::from_utf8_lossy(&bytes[..n]);
                let fields = text
                    .trim_matches('\0')
                    .trim()
                    .split(':')
                    .collect::<Vec<_>>();
                if fields.first() == Some(&"ClamAV-VDB") {
                    let time = handle
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
                    files.push(json!({"name":name,"databaseDate":fields.get(1).unwrap_or(&""),"version":fields.get(2).unwrap_or(&""),"signatures":fields.get(3).and_then(|v|v.parse::<u64>().ok()).unwrap_or(0),"updatedAt":time}));
                }
            }
        }
    }
    let daily = files
        .iter()
        .find(|f| f["name"].as_str().unwrap_or("").starts_with("daily"));
    let main = files
        .iter()
        .any(|f| f["name"].as_str().unwrap_or("").starts_with("main"));
    json!({"ready":daily.is_some()&&main,"updatedAt":daily.map(|d|d["updatedAt"].clone()),"count":files.iter().filter_map(|f|f["signatures"].as_u64()).sum::<u64>(),"files":files})
}
pub fn status(core: &Core) -> Result<Value> {
    let db = core.dir.join("signatures");
    let scanner = engine(&core.resources, "clamav", "clamscan");
    let version = scanner
        .as_ref()
        .and_then(|file| {
            capture(
                file,
                &["--version".into()],
                10,
                None,
                &runtime_env(&core.resources, "clamav"),
            )
            .ok()
        })
        .filter(|o| o.code == 0)
        .map(|o| o.text);
    let scans = core.store.lock().map_err(|_| "state-lock")?.data["scans"].clone();
    Ok(
        json!({"engine":"ClamAV","installed":scanner.is_some(),"updaterAvailable":engine(&core.resources,"clamav","freshclam").is_some(),"version":version,"runnable":version.is_some(),"signatures":signatures(&db),"job":core.job.lock().map_err(|_|"job-lock")?.clone(),"scans":scans,"realtime":false}),
    )
}
#[derive(Default)]
pub struct ScanOutput {
    pub tail: String,
    pub threats: Vec<Value>,
    pub detected: u64,
    pub partial: bool,
    pub issues: Vec<Value>,
}
impl ScanOutput {
    pub fn accept(&mut self, line: &str) {
        self.tail.push_str(line);
        self.tail.push('\n');
        if self.tail.len() > 131072 {
            let mut start = self.tail.len() - 131072;
            while !self.tail.is_char_boundary(start) {
                start += 1;
            }
            self.tail = self.tail[start..].into();
        }
        if [
            "Heuristics.Limits.Exceeded",
            "size limit reached",
            "Scanning limit reached",
            "ERROR:",
            "Permission denied",
            "Access is denied",
            "Can't open file",
        ]
        .iter()
        .any(|s| line.contains(s))
        {
            self.partial = true;
        }
        if (line.ends_with(" ERROR")
            || line.starts_with("ERROR:")
            || line.contains("Permission denied")
            || line.contains("Access is denied"))
            && self.issues.len() < 200
        {
            let (path, detail) = line.rsplit_once(": ").unwrap_or(("", line));
            let item = crate::scan_plan::issue(path, detail);
            if !self.issues.contains(&item) {
                self.issues.push(item);
            }
        }
        if let Some(found) = line.strip_suffix(" FOUND") {
            if let Some((file, name)) = found.rsplit_once(": ") {
                self.detected += 1;
                if self.threats.len() < 2000 {
                    self.threats.push(json!({"path":file,"name":name}));
                }
            }
        }
    }
    pub fn result(&self, code: i32) -> Value {
        let number = |name: &str| {
            Regex::new(&format!(r"(?mi)^{}:\s*(\d+)", regex::escape(name)))
                .unwrap()
                .captures(&self.tail)
                .and_then(|c| c[1].parse::<u64>().ok())
        };
        let scanned = number("Scanned files");
        let infected = number("Infected files").unwrap_or(0).max(self.detected);
        let errors = number("Total errors").unwrap_or(0);
        let limited = self.tail.contains("Limits.Exceeded") || self.tail.contains("limit reached");
        let partial =
            self.partial || limited || errors > 0 || code != 0 && code != 1 || scanned.is_none();
        json!({"scanned":scanned,"infected":infected,"errors":errors,"limited":limited,"partial":partial,"issues":self.issues,"exitCode":code,"threats":self.threats,"threatsTruncated":infected>self.threats.len() as u64,"state":if infected>0{"threats"}else if code==0&&!partial{"completed"}else{"error"}})
    }
}
fn reserve(core: &Core) -> Result<()> {
    let _slot = core.scan_child.lock().map_err(|_| "process-lock")?;
    if core.closing.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    if core
        .scan_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("antivirus-busy".into());
    }
    core.scan_cancel.store(false, Ordering::SeqCst);
    Ok(())
}
pub fn cancel(core: &Core) -> Result<()> {
    let _slot = core.scan_child.lock().map_err(|_| "process-lock")?;
    core.scan_cancel.store(true, Ordering::SeqCst);
    Ok(())
}
pub fn start(
    core: &Core,
    app: &tauri::AppHandle,
    kind: &str,
    selected: Option<PathBuf>,
) -> Result<Value> {
    reserve(core)?;
    let started = start_inner(core, app, kind, selected);
    if started.is_err() {
        core.scan_busy.store(false, Ordering::SeqCst);
        if let Ok(mut job) = core.job.lock() {
            if job["state"] == "preparing" {
                job["state"] = json!(if core.scan_cancel.load(Ordering::SeqCst) {
                    "cancelled"
                } else {
                    "error"
                });
                job["error"] = json!(started.as_ref().err());
                job["endedAt"] = json!(store::now());
                if let Ok(mut s) = core.store.lock() {
                    s.data["activeScan"] = Value::Null;
                    if s.push("scans", job.clone(), 50).is_err() {
                        job["persistenceError"] = json!("result-not-saved");
                    }
                }
                let _ = app.emit(
                    "aegis:event",
                    json!({"type":"antivirus","data":job.clone()}),
                );
            }
        }
    }
    started
}
fn start_inner(
    core: &Core,
    app: &tauri::AppHandle,
    kind: &str,
    selected: Option<PathBuf>,
) -> Result<Value> {
    let db = core.dir.join("signatures");
    store::private_dir(&db)?;
    let (binary, mut args, targets) = if kind == "update" {
        let binary =
            engine(&core.resources, "clamav", "freshclam").ok_or("freshclam-unavailable")?;
        let config = core.dir.join("freshclam.conf");
        let directory = db.to_string_lossy().replace('\\', "/").replace('"', "");
        let mut text=format!("DatabaseDirectory \"{directory}\"\nDatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\nScriptedUpdates yes\nTestDatabases yes\nConnectTimeout 30\nReceiveTimeout 120\nMaxAttempts 2\nBytecode yes\n");
        if !cfg!(windows) {
            let name = std::env::var("USER").unwrap_or_default();
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
            {
                text.push_str(&format!("DatabaseOwner {name}\n"));
            }
        }
        store::write_private(&config, text.as_bytes(), false)?;
        (
            binary,
            vec![
                format!("--config-file={}", config.display()),
                "--stdout".into(),
            ],
            vec![],
        )
    } else {
        if !["quick", "full", "custom"].contains(&kind) {
            return Err("invalid-scan-type".into());
        }
        let binary = engine(&core.resources, "clamav", "clamscan").ok_or("clamav-unavailable")?;
        if signatures(&db)["ready"] != true {
            return Err("signatures-required".into());
        }
        let targets = match kind {
            "custom" => vec![selected.ok_or("selection-required")?],
            "full" => {
                if cfg!(windows) {
                    vec![PathBuf::from(
                        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()) + "\\",
                    )]
                } else {
                    vec![PathBuf::from("/")]
                }
            }
            _ => quick_targets([
                app.path().download_dir().ok(),
                app.path().desktop_dir().ok(),
            ]),
        };
        if targets.is_empty() || targets.iter().any(|p| !p.is_absolute() || !p.exists()) {
            return Err("selection-required".into());
        }
        let mut args = vec![
            format!("--database={}", db.display()),
            "--recursive".into(),
            "--verbose".into(),
            "--stdout".into(),
            "--allmatch".into(),
            "--cross-fs=no".into(),
            "--follow-dir-symlinks=0".into(),
            "--follow-file-symlinks=0".into(),
        ];
        if !cfg!(windows) {
            args.extend([
                "--exclude-dir=^/proc(/|$)".into(),
                "--exclude-dir=^/sys(/|$)".into(),
                "--exclude-dir=^/dev(/|$)".into(),
            ]);
        }
        args.push("--".into());
        args.extend(targets.iter().map(|p| p.to_string_lossy().into_owned()));
        (binary, args, targets)
    };
    let task_id = store::id();
    let mut plan = None;
    if kind != "update" {
        let preparing = json!({"id":task_id,"type":kind,"state":"preparing","startedAt":store::now(),"targets":targets,"lines":[],"progress":{"phase":"inventory","discovered":0,"processed":0,"total":null,"percent":null}});
        *core.job.lock().map_err(|_| "job-lock")? = preparing.clone();
        {
            let mut s = core.store.lock().map_err(|_| "state-lock")?;
            s.data["activeScan"] = preparing.clone();
            s.save()?;
        }
        let _ = app.emit("aegis:event", json!({"type":"antivirus","data":preparing}));
        let mut excluded = crate::scan_plan::excluded(&core.dir);
        excluded.extend(crate::quarantine::pending_files(core)?);
        let prepared = crate::scan_plan::build(
            &targets,
            &excluded,
            core.dir.join(format!("scan-{task_id}.list")),
            &core.scan_cancel,
            |count| {
                if let Ok(mut job) = core.job.lock() {
                    job["progress"]["discovered"] = json!(count);
                    let _ = app.emit(
                        "aegis:event",
                        json!({"type":"antivirus","data":job.clone()}),
                    );
                }
            },
        )?;
        if prepared.files.is_empty() {
            return Err("scan-no-readable-files".into());
        }
        let marker = args
            .iter()
            .position(|a| a == "--")
            .ok_or("invalid-scan-type")?;
        args.truncate(marker);
        args.push(format!("--file-list={}", prepared.path.display()));
        plan = Some(prepared);
    }
    let mut cmd = command(&binary, &args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in runtime_env(&core.resources, "clamav") {
        cmd.env(k, v);
    }
    let mut slot = core.scan_child.lock().map_err(|_| "process-lock")?;
    if core.scan_cancel.load(Ordering::SeqCst) || core.closing.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("missing-process-output")?;
    let stderr = child.stderr.take().ok_or("missing-process-output")?;
    let job = json!({"id":task_id,"type":kind,"state":"running","startedAt":store::now(),"targets":targets,"lines":[],"progress":{"phase":if kind=="update"{"download"}else{"scan"},"processed":0,"total":plan.as_ref().map(|p|p.files.len()),"percent":if kind=="update"{Value::Null}else{json!(0)},"current":null}});
    *core.job.lock().map_err(|_| "job-lock")? = job.clone();
    *slot = Some(child);
    drop(slot);
    {
        let mut store = core.store.lock().map_err(|_| "state-lock")?;
        store.data["activeScan"] = job.clone();
        if let Err(error) = store.save() {
            if let Some(child) = core.scan_child.lock().map_err(|_| "process-lock")?.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
            *core.scan_child.lock().map_err(|_| "process-lock")? = None;
            return Err(error);
        }
    }
    let (tx, rx) = std::sync::mpsc::sync_channel::<String>(SCAN_OUTPUT_BATCH);
    for pipe in [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)] {
        let sender = tx.clone();
        thread::spawn(move || {
            let mut reader = BufReader::new(pipe);
            loop {
                let mut bytes = Vec::new();
                let mut limited = reader.by_ref().take(65536);
                let read = limited.read_until(b'\n', &mut bytes);
                if !matches!(read,Ok(n) if n>0) {
                    break;
                }
                if sender
                    .send(String::from_utf8_lossy(&bytes).trim_end().into())
                    .is_err()
                {
                    break;
                }
            }
        });
    }
    drop(tx);
    let state = core.clone();
    let handle = app.clone();
    let task_type = kind.to_string();
    let _ = app.emit("aegis:event", json!({"type":"antivirus","data":job}));
    thread::spawn(move || {
        let mut output = ScanOutput::default();
        let mut processed = HashSet::new();
        let mut exit = None;
        let mut checkpoint = std::time::Instant::now();
        loop {
            drain_output_batch(&rx, &state.scan_cancel, |line| {
                output.accept(line);
                if let Ok(mut job) = state.job.lock() {
                    if let Some(plan) = &plan {
                        crate::scan_plan::track(line, &mut job, &plan.files, &mut processed);
                    }
                    let lines = job["lines"].as_array_mut().unwrap();
                    lines.push(json!(line.chars().take(1500).collect::<String>()));
                    if lines.len() > 120 {
                        lines.remove(0);
                    }
                }
            });
            if let Ok(mut child) = state.scan_child.lock() {
                if let Some(child) = child.as_mut() {
                    if state.scan_cancel.load(Ordering::SeqCst) {
                        let _ = child.kill();
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => exit = Some(status.code().unwrap_or(-1)),
                        Err(_) => exit = Some(-1),
                        _ => (),
                    }
                } else {
                    exit = Some(-1);
                }
            }
            if exit.is_some() {
                break;
            }
            if checkpoint.elapsed() >= Duration::from_secs(2) {
                let snapshot = state.job.lock().ok().map(|mut job| {
                    if task_type != "update" {
                        let mut progress = output.result(2);
                        progress["partial"] = json!(output.partial);
                        progress["state"] = json!("running");
                        job["summary"] = progress;
                    }
                    job.clone()
                });
                if let Some(snapshot) = snapshot {
                    if let Ok(mut store) = state.store.lock() {
                        store.data["activeScan"] = snapshot;
                        if store.save().is_err() {
                            if let Ok(mut job) = state.job.lock() {
                                job["persistenceError"] = json!("result-not-saved");
                            }
                        }
                    }
                }
                checkpoint = std::time::Instant::now();
            }
            if let Ok(job) = state.job.lock() {
                let _ = handle.emit(
                    "aegis:event",
                    json!({"type":"antivirus","data":job.clone()}),
                );
            }
            thread::sleep(Duration::from_millis(200));
        }
        for line in rx {
            output.accept(&line);
            if let Ok(mut job) = state.job.lock() {
                if let Some(plan) = &plan {
                    crate::scan_plan::track(&line, &mut job, &plan.files, &mut processed);
                }
                let lines = job["lines"].as_array_mut().unwrap();
                lines.push(json!(line.chars().take(1500).collect::<String>()));
                if lines.len() > 120 {
                    lines.remove(0);
                }
            }
        }
        if let Ok(mut child) = state.scan_child.lock() {
            *child = None;
        }
        if let Ok(mut job) = state.job.lock() {
            let cancelled = state.scan_cancel.load(Ordering::SeqCst);
            job["endedAt"] = json!(store::now());
            if task_type != "update" {
                job["summary"] = output.result(exit.unwrap_or(-1));
                if let Some(plan) = &plan {
                    job["summary"]["skipped"] = json!(plan.skipped);
                    job["summary"]["errors"] =
                        json!(job["summary"]["errors"].as_u64().unwrap_or(0) + plan.error_count);
                    if !plan.errors.is_empty()
                        || plan.limited
                        || processed.len() != plan.files.len()
                    {
                        job["summary"]["partial"] = json!(true);
                    }
                    job["summary"]["limited"] =
                        json!(plan.limited || job["summary"]["limited"] == true);
                    if let Some(issues) = job["summary"]["issues"].as_array_mut() {
                        issues.extend(plan.errors.iter().cloned());
                        issues.truncate(200);
                    }
                    if exit == Some(0) && processed.len() == plan.files.len() {
                        job["progress"]["percent"] = json!(100);
                    }
                }
                if cancelled {
                    job["summary"]["partial"] = json!(true);
                }
                job["state"] = if cancelled {
                    json!("cancelled")
                } else {
                    job["summary"]["state"].clone()
                };
                if job["state"] == "completed" && job["summary"]["partial"] == true {
                    job["state"] = json!("partial");
                }
            } else {
                job["state"] = json!(if cancelled {
                    "cancelled"
                } else if exit == Some(0) {
                    "completed"
                } else {
                    "error"
                });
            }
            if job["state"] == "error" {
                let lower = output.tail.to_lowercase();
                let cause = if lower.contains("429")
                    || lower.contains("cool-down")
                    || lower.contains("cooldown")
                {
                    "rate-limit"
                } else if lower.contains("403") {
                    "download-denied"
                } else if lower.contains("certificate") || lower.contains("ssl") {
                    "certificate"
                } else if lower.contains("resolve")
                    || lower.contains("connect")
                    || lower.contains("timeout")
                {
                    "network"
                } else if lower.contains("database") {
                    "database"
                } else if !output.issues.is_empty() {
                    "read"
                } else {
                    "engine"
                };
                job["failure"] = json!({"cause":cause,"exitCode":exit,"detail":output.tail.lines().filter(|l|!l.trim().is_empty()).rev().take(12).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n")});
            }
            job.as_object_mut().unwrap().remove("persistenceError");
            if let Ok(mut store) = state.store.lock() {
                store.data["activeScan"] = Value::Null;
                let saved = store.push("scans", job.clone(), 50).and_then(|_| {
                    store.event(
                        "antivirus",
                        if task_type == "update" {
                            "Atualização de assinaturas"
                        } else {
                            "Varredura concluída"
                        },
                        json!({"scanned":job["summary"]["scanned"],"infected":job["summary"]["infected"],"errors":job["summary"]["errors"],"partial":job["summary"]["partial"]}),
                        if job["state"] == "completed" {
                            "success"
                        } else {
                            "warning"
                        },
                    )
                });
                if saved.is_err() {
                    job["persistenceError"] = json!("result-not-saved");
                }
            }
            let _ = handle.emit(
                "aegis:event",
                json!({"type":"antivirus","data":job.clone()}),
            );
        }
        state.scan_busy.store(false, Ordering::SeqCst);
    });
    Ok(job)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_of_reserved_scan_is_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let core = Core::new(directory.path().into(), directory.path().into()).unwrap();
        reserve(&core).unwrap();
        cancel(&core).unwrap();
        assert!(reserve(&core).is_err());
        assert!(core.scan_cancel.load(Ordering::SeqCst));
        assert!(core.scan_child.lock().unwrap().is_none());
    }
    #[test]
    fn output_flood_yields_to_cancellation() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send("first output".to_string()).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut processed = 0;
        drain_output_batch(&receiver, &cancelled, |_| {
            processed += 1;
            sender.send("more output".to_string()).unwrap();
            cancelled.store(true, Ordering::SeqCst);
        });
        assert_eq!(processed, 1);
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(
            receiver.try_recv().is_ok(),
            "output remains queued while cancellation can be handled"
        );
    }
    #[test]
    fn output_flood_cannot_starve_process_exit_polling() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send("first output".to_string()).unwrap();
        let mut processed = 0;
        drain_output_batch(&receiver, &AtomicBool::new(false), |_| {
            processed += 1;
            sender.send("more output".to_string()).unwrap();
        });
        assert_eq!(processed, SCAN_OUTPUT_BATCH);
        assert!(receiver.try_recv().is_ok());
    }
    #[test]
    fn quick_scan_uses_resolved_redirected_folders_without_english_fallbacks() {
        let root = tempfile::tempdir().unwrap();
        let downloads = root.path().join("Baixados personalizados");
        let desktop = root.path().join("OneDrive").join("Área de Trabalho");
        fs::create_dir_all(&downloads).unwrap();
        fs::create_dir_all(&desktop).unwrap();
        assert_eq!(
            quick_targets([Some(downloads.clone()), Some(desktop.clone())]),
            vec![downloads.clone(), desktop]
        );
        assert_eq!(
            quick_targets([Some(downloads.clone()), Some(downloads.clone())]),
            vec![downloads]
        );
    }
    #[test]
    fn quick_scan_has_no_successful_empty_or_file_target() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("not-a-directory");
        fs::write(&file, "fixture").unwrap();
        assert!(quick_targets([Some(file), Some(root.path().join("missing")), None]).is_empty());
    }
    #[test]
    fn detection_survives_truncated_output() {
        let mut out = ScanOutput::default();
        out.accept("/tmp/test: Eicar-Test-Signature FOUND");
        for _ in 0..6000 {
            out.accept("long harmless output without detections");
        }
        out.accept("Scanned files: 1");
        out.accept("Total errors: 1");
        let result = out.result(2);
        assert_eq!(result["infected"], 1);
        assert_eq!(result["state"], "threats");
        assert_eq!(result["partial"], true);
    }
    #[test]
    fn no_summary_never_passes() {
        assert_eq!(ScanOutput::default().result(0)["state"], "error");
    }
    #[test]
    fn completed_requires_zero_errors() {
        let mut out = ScanOutput::default();
        out.accept("Scanned files: 42");
        out.accept("Infected files: 0");
        assert_eq!(out.result(0)["state"], "completed");
        assert_eq!(out.result(2)["state"], "error");
    }
}
