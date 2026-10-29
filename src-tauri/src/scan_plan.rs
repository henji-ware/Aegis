use crate::store::{self, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
pub const MAX_ENGINE_FILE_BYTES: u64 = i32::MAX as u64;
pub fn size_issue(path: &str, bytes: u64, detail: &str) -> Value {
    json!({"path":path,"kind":"size","bytes":bytes,"limit":MAX_ENGINE_FILE_BYTES,"detail":detail})
}

pub fn identity(path: &str) -> [u8; 32] {
    let value = if cfg!(windows) {
        path.trim_start_matches(r"\\?\")
            .replace('/', "\\")
            .to_lowercase()
    } else {
        path.to_string()
    };
    Sha256::digest(value.as_bytes()).into()
}
fn within(file: &Path, parent: &Path) -> bool {
    #[cfg(windows)]
    {
        let clean = |p: &Path| {
            PathBuf::from(
                p.to_string_lossy()
                    .trim_start_matches(r"\\?\")
                    .to_lowercase(),
            )
        };
        clean(file).starts_with(clean(parent))
    }
    #[cfg(not(windows))]
    {
        file.starts_with(parent)
    }
}
pub fn track(line: &str, job: &mut Value, known: &HashSet<[u8; 32]>, seen: &mut HashSet<[u8; 32]>) {
    if let Some(file) = line.strip_prefix("Scanning ") {
        if known.contains(&identity(file)) {
            job["progress"]["current"] = json!(file);
        }
    }
    if let Some((file, detail)) = line.rsplit_once(": ") {
        if detail == "OK" || detail.ends_with(" FOUND") || detail.ends_with(" ERROR") {
            let key = identity(file);
            if known.contains(&key) {
                seen.insert(key);
                job["progress"]["processed"] = json!(seen.len());
                job["progress"]["percent"] = json!(seen.len() * 100 / known.len().max(1));
            }
        }
    }
}
pub fn issue(path: &str, detail: &str) -> Value {
    let lower = detail.to_lowercase();
    if lower.contains("file status") || lower.contains("fstat") {
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > MAX_ENGINE_FILE_BYTES {
                return size_issue(path, meta.len(), detail);
            }
        }
    }
    let kind =
        if lower.contains("permission") || lower.contains("access") || lower.contains("denied") {
            "permission"
        } else if lower.contains("not found")
            || lower.contains("no such")
            || lower.contains("cannot find")
        {
            "missing"
        } else if lower.contains("limit") || lower.contains("too large") {
            "limit"
        } else if lower.contains("encrypted") || lower.contains("password") {
            "encrypted"
        } else if lower.contains("database") || lower.contains("signature") {
            "database"
        } else {
            "read"
        };
    json!({"path":path,"kind":kind,"detail":detail.chars().take(1500).collect::<String>()})
}
pub struct Plan {
    pub path: PathBuf,
    pub files: HashSet<[u8; 32]>,
    pub errors: Vec<Value>,
    pub error_count: u64,
    pub size_limited: u64,
    pub skipped: u64,
    pub limited: bool,
}
impl Drop for Plan {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
pub fn build(
    targets: &[PathBuf],
    excluded: &[PathBuf],
    path: PathBuf,
    cancel: &AtomicBool,
    mut progress: impl FnMut(usize),
) -> Result<Plan> {
    let mut plan = Plan {
        path,
        files: HashSet::new(),
        errors: vec![],
        error_count: 0,
        size_limited: 0,
        skipped: 0,
        limited: false,
    };
    store::write_private(&plan.path, b"", true)?;
    let mut out = fs::OpenOptions::new()
        .append(true)
        .open(&plan.path)
        .map_err(|e| e.to_string())?;
    let mut stack = targets
        .iter()
        .map(|p| {
            #[cfg(unix)]
            let volume = {
                use std::os::unix::fs::MetadataExt;
                fs::symlink_metadata(p).ok().map(|m| m.dev())
            };
            #[cfg(not(unix))]
            let volume: Option<u64> = None;
            (p.clone(), volume)
        })
        .collect::<Vec<_>>();
    let mut dirs = HashSet::new();
    let mut tick = Instant::now();
    let mut bytes = 0;
    while let Some((file, volume)) = stack.pop() {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        if excluded.iter().any(|p| within(&file, p)) {
            plan.skipped += 1;
            continue;
        }
        let meta = match fs::symlink_metadata(&file) {
            Ok(m) => m,
            Err(e) => {
                plan.error_count += 1;
                if plan.errors.len() < 200 {
                    plan.errors
                        .push(issue(&file.to_string_lossy(), &e.to_string()));
                }
                plan.skipped += 1;
                continue;
            }
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if volume.is_some_and(|d| d != meta.dev()) {
                plan.skipped += 1;
                continue;
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                plan.skipped += 1;
                plan.error_count += 1;
                if plan.errors.len() < 200 {
                    plan.errors.push(issue(
                        &file.to_string_lossy(),
                        "Cloud placeholder, link or reparse-point item was not followed",
                    ));
                }
                continue;
            }
        }
        if meta.file_type().is_symlink() {
            plan.skipped += 1;
            continue;
        }
        if meta.is_dir() {
            let canonical = match file.canonicalize() {
                Ok(path) => path,
                Err(error) => {
                    plan.skipped += 1;
                    plan.error_count += 1;
                    if plan.errors.len() < 200 {
                        plan.errors
                            .push(issue(&file.to_string_lossy(), &error.to_string()));
                    }
                    continue;
                }
            };
            if !dirs.insert(canonical) {
                continue;
            }
            match fs::read_dir(&file) {
                Ok(entries) => {
                    for entry in entries {
                        match entry {
                            Ok(e) => {
                                if stack.len() >= 1_000_000 {
                                    plan.limited = true;
                                    break;
                                }
                                stack.push((e.path(), volume));
                            }
                            Err(e) => {
                                plan.skipped += 1;
                                plan.error_count += 1;
                                if plan.errors.len() < 200 {
                                    plan.errors
                                        .push(issue(&file.to_string_lossy(), &e.to_string()));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    plan.skipped += 1;
                    plan.error_count += 1;
                    if plan.errors.len() < 200 {
                        plan.errors
                            .push(issue(&file.to_string_lossy(), &e.to_string()));
                    }
                }
            }
        } else if meta.is_file() {
            if meta.len() > MAX_ENGINE_FILE_BYTES {
                plan.skipped += 1;
                plan.size_limited += 1;
                if plan.errors.len() < 200 {
                    plan.errors.push(size_issue(
                        &file.to_string_lossy(),
                        meta.len(),
                        "ClamAV cannot analyze files of 2 GiB or larger; file was not scanned.",
                    ));
                }
                continue;
            }
            let text = file.to_str().filter(|s| !s.contains(['\n', '\r']));
            if let Some(text) = text {
                if !plan.files.insert(identity(text)) {
                    continue;
                }
                bytes += text.len() + 1;
                if bytes > 128 * 1024 * 1024 || plan.files.len() > 1_000_000 {
                    plan.files.remove(&identity(text));
                    plan.limited = true;
                    break;
                }
                writeln!(out, "{text}").map_err(|e| e.to_string())?;
            } else {
                plan.skipped += 1;
                plan.error_count += 1;
                if plan.errors.len() < 200 {
                    plan.errors
                        .push(issue(&file.to_string_lossy(), "Unsupported file-list name"));
                }
            }
        } else {
            plan.skipped += 1;
        }
        if tick.elapsed().as_millis() > 250 {
            progress(plan.files.len());
            tick = Instant::now();
        }
    }
    out.sync_all().map_err(|e| e.to_string())?;
    progress(plan.files.len());
    Ok(plan)
}
pub fn excluded(data: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data.to_path_buf()];
    if cfg!(unix) {
        paths.extend(["/proc", "/sys", "/dev"].map(PathBuf::from));
    }
    paths
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_excludes_symlinks_and_private_state_and_deduplicates() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("keep"), "private").unwrap();
        fs::write(root.path().join("sample"), "benign").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path(), root.path().join("loop")).unwrap();
        let plan = build(
            &[root.path().into(), root.path().join("sample")],
            &[data.clone()],
            data.join("list"),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(plan.files.len(), 1);
        assert!(plan
            .files
            .contains(&identity(&root.path().join("sample").to_string_lossy())));
    }
    #[test]
    fn cancelled_inventory_removes_manifest() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("list");
        assert!(build(
            &[root.path().into()],
            &[],
            file.clone(),
            &AtomicBool::new(true),
            |_| {}
        )
        .is_err());
        assert!(!file.exists());
    }
    #[test]
    fn errors_have_actionable_categories() {
        assert_eq!(issue("file", "Permission denied")["kind"], "permission");
        assert_eq!(issue("file", "No such file")["kind"], "missing");
    }
    #[test]
    fn oversized_file_is_reported_without_sending_it_to_the_engine() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("large-video.mkv");
        let handle = fs::File::create(&file).unwrap();
        handle.set_len(MAX_ENGINE_FILE_BYTES + 1).unwrap();
        drop(handle);
        let plan = build(
            &[file.clone()],
            &[],
            root.path().join("scan.list"),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert!(plan.files.is_empty());
        assert_eq!(plan.size_limited, 1);
        assert_eq!(plan.error_count, 0);
        assert_eq!(plan.errors[0]["kind"], "size");
        assert_eq!(plan.errors[0]["bytes"], MAX_ENGINE_FILE_BYTES + 1);
        assert!(fs::read_to_string(&plan.path).unwrap().is_empty());
        assert_eq!(
            issue(&file.to_string_lossy(), "Can't get file status ERROR")["kind"],
            "size"
        );
    }
    #[test]
    fn progress_ignores_archive_subitems_and_duplicate_matches() {
        let known = HashSet::from([identity("/data/file.zip")]);
        let mut seen = HashSet::new();
        let mut job = json!({"progress":{}});
        track(
            "/data/file.zip!inner: Sample FOUND",
            &mut job,
            &known,
            &mut seen,
        );
        assert!(seen.is_empty());
        track(
            "/data/file.zip: Test.One FOUND",
            &mut job,
            &known,
            &mut seen,
        );
        track(
            "/data/file.zip: Test.Two FOUND",
            &mut job,
            &known,
            &mut seen,
        );
        assert_eq!(seen.len(), 1);
        assert_eq!(job["progress"]["percent"], 100);
    }
}
