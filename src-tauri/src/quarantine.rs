use crate::{
    runner::*,
    store::{self, Result},
    Core,
};
use base64::{engine::general_purpose::STANDARD, read::DecoderReader, write::EncoderWriter};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};
const HEADER: &[u8] = b"AEGIS-QUARANTINE-1\n";
const MAX: u64 = 512 * 1024 * 1024;
fn hash(path: &Path) -> Result<String> {
    let mut f = open_regular(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn open_regular(path: &Path) -> Result<fs::File> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX {
        return Err("quarantine-unsupported-file".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err("quarantine-unsupported-file".into());
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata().map_err(|e| e.to_string())?.nlink() != 1 {
            return Err("quarantine-hard-links".into());
        }
    }
    Ok(file)
}
fn owned(core: &Core, id: &str, suffix: &str) -> Result<PathBuf> {
    if uuid::Uuid::parse_str(id).is_err() {
        return Err("invalid-quarantine-item".into());
    }
    Ok(core.dir.join("quarantine").join(format!("{id}.{suffix}")))
}
fn save(core: &Core, entry: &Value) -> Result<()> {
    let mut s = core.store.lock().map_err(|_| "state-lock")?;
    let list = s.data["quarantine"]
        .as_array_mut()
        .ok_or("invalid-local-data")?;
    if let Some(old) = list.iter_mut().find(|v| v["id"] == entry["id"]) {
        *old = entry.clone();
    } else {
        if list.len() >= 500 {
            return Err("quarantine-limit".into());
        }
        list.insert(0, entry.clone());
    }
    s.save()
}
pub fn list(core: &Core) -> Result<Value> {
    let s = core.store.lock().map_err(|_| "state-lock")?;
    Ok(s.data["quarantine"].clone())
}
fn blocked(core: &Core, path: &Path) -> bool {
    if path.starts_with(&core.dir) || path.starts_with(&core.resources) {
        return true;
    }
    if cfg!(windows) {
        std::env::var_os("SystemRoot").is_some_and(|p| path.starts_with(PathBuf::from(p)))
    } else {
        ["/bin", "/sbin", "/usr", "/lib", "/etc", "/boot", "/System"]
            .iter()
            .any(|p| path.starts_with(p))
    }
}
pub fn isolate(core: &Core, scan: &str, index: usize) -> Result<Value> {
    if core.scan_busy.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("antivirus-busy".into());
    }
    let threat = {
        let s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["scans"]
            .as_array()
            .and_then(|items| items.iter().find(|s| s["id"] == scan))
            .and_then(|s| s["summary"]["threats"].as_array())
            .and_then(|t| t.get(index))
            .cloned()
            .ok_or("invalid-quarantine-item")?
    };
    let original = PathBuf::from(threat["path"].as_str().ok_or("invalid-quarantine-item")?);
    open_regular(&original)?;
    let original = original.canonicalize().map_err(|e| e.to_string())?;
    if blocked(core, &original) {
        return Err("quarantine-protected-file".into());
    }
    // Recheck the selected detection with the current definitions before moving it.
    let scanner = engine(&core.resources, "clamav", "clamscan").ok_or("clamav-unavailable")?;
    let before = hash(&original)?;
    let result = capture(
        &scanner,
        &[
            format!("--database={}", core.dir.join("signatures").display()),
            "--infected".into(),
            "--stdout".into(),
            "--follow-file-symlinks=0".into(),
            "--".into(),
            original.to_string_lossy().into_owned(),
        ],
        120,
        None,
        &runtime_env(&core.resources, "clamav"),
    )?;
    if result.code != 1 || !result.text.lines().any(|l| l.ends_with(" FOUND")) {
        return Err("quarantine-detection-changed".into());
    }
    if hash(&original)? != before {
        return Err("quarantine-file-changed".into());
    }
    let id = store::id();
    let directory = core.dir.join("quarantine");
    store::private_dir(&directory)?;
    let pending = owned(core, &id, "pending")?;
    let container = owned(core, &id, "aegis")?;
    let permissions = fs::metadata(&original)
        .map_err(|e| e.to_string())?
        .permissions();
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        permissions.mode() & 0o777
    };
    #[cfg(not(unix))]
    let mode = if permissions.readonly() { 1 } else { 0 };
    let mut entry = json!({"id":id,"at":store::now(),"original":original,"name":original.file_name().unwrap_or_default().to_string_lossy(),"detection":threat["name"],"sha256":before,"mode":mode,"state":"pending"});
    save(core, &entry)?;
    fs::rename(&original, &pending).map_err(|e| format!("quarantine-move-failed: {e}"))?;
    // If the name changed during the move, retain a recoverable pending item.
    if hash(&pending)? != before {
        return Err("quarantine-file-changed".into());
    }
    store::write_private(&container, HEADER, true)?;
    let file = fs::OpenOptions::new()
        .append(true)
        .open(&container)
        .map_err(|e| e.to_string())?;
    let mut encoder = EncoderWriter::new(file, &STANDARD);
    let mut input = open_regular(&pending)?;
    std::io::copy(&mut input, &mut encoder).map_err(|e| e.to_string())?;
    let file = encoder.finish().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    if hash(&pending)? != before {
        return Err("quarantine-file-changed".into());
    }
    drop(input);
    fs::remove_file(&pending).map_err(|e| e.to_string())?;
    entry["state"] = json!("isolated");
    save(core, &entry)?;
    list(core)
}
pub fn restore(core: &Core, id: &str) -> Result<Value> {
    let mut entry = {
        let s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["quarantine"]
            .as_array()
            .and_then(|items| items.iter().find(|e| e["id"] == id))
            .cloned()
            .ok_or("invalid-quarantine-item")?
    };
    if !matches!(entry["state"].as_str(), Some("isolated" | "pending")) {
        return Err("invalid-quarantine-item".into());
    }
    let original = PathBuf::from(
        entry["original"]
            .as_str()
            .ok_or("invalid-quarantine-item")?,
    );
    if !original.is_absolute() || blocked(core, &original) {
        return Err("quarantine-protected-file".into());
    }
    if original.try_exists().map_err(|e| e.to_string())? {
        return Err("quarantine-restore-conflict".into());
    }
    let pending = owned(core, id, "pending")?;
    if pending.exists() {
        // Restore through a new file so a concurrently created destination is never overwritten.
        let mut input = open_regular(&pending)?;
        store::write_private(&original, b"", true)?;
        let result = (|| -> Result<()> {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .open(&original)
                .map_err(|e| e.to_string())?;
            std::io::copy(&mut input, &mut out).map_err(|e| e.to_string())?;
            out.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&original);
            return Err(e);
        }
    } else {
        let mut input = fs::File::open(owned(core, id, "aegis")?).map_err(|e| e.to_string())?;
        let mut header = vec![0; HEADER.len()];
        input.read_exact(&mut header).map_err(|e| e.to_string())?;
        if header != HEADER {
            return Err("quarantine-integrity".into());
        }
        store::write_private(&original, b"", true)?;
        let result = (|| -> Result<()> {
            let mut output = fs::OpenOptions::new()
                .write(true)
                .open(&original)
                .map_err(|e| e.to_string())?;
            let count = std::io::copy(
                &mut DecoderReader::new(input, &STANDARD).take(MAX + 1),
                &mut output,
            )
            .map_err(|e| e.to_string())?;
            if count > MAX {
                return Err("quarantine-integrity".into());
            }
            output.sync_all().map_err(|e| e.to_string())?;
            if hash(&original)? != entry["sha256"].as_str().unwrap_or("") {
                return Err("quarantine-integrity".into());
            }
            Ok(())
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&original);
            return Err(e);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &original,
            fs::Permissions::from_mode(entry["mode"].as_u64().unwrap_or(0o600) as u32 & 0o777),
        )
        .map_err(|e| e.to_string())?;
    }
    entry["state"] = json!("restored");
    entry["restoredAt"] = json!(store::now());
    save(core, &entry)?;
    for suffix in ["aegis", "pending"] {
        let path = owned(core, id, suffix)?;
        if path.exists() {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    list(core)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unowned_paths_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::new(root.path().into(), root.path().into()).unwrap();
        assert!(owned(&core, "../../file", "pending").is_err());
        let f = root.path().join("f");
        fs::write(&f, "fixture").unwrap();
        assert!(open_regular(&f).is_ok());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&f, root.path().join("link")).unwrap();
            assert!(open_regular(&root.path().join("link")).is_err());
        }
    }
    #[test]
    fn restore_never_overwrites_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let core = Core::new(data.clone(), data.join("engines")).unwrap();
        let file = root.path().join("keep");
        fs::write(&file, "original").unwrap();
        let id = store::id();
        save(&core, &json!({"id":id,"state":"isolated","original":file})).unwrap();
        assert!(restore(&core, &id).is_err());
        assert_eq!(fs::read_to_string(file).unwrap(), "original");
    }
}
