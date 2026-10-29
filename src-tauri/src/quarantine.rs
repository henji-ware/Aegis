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
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if info.nNumberOfLinks != 1 {
            return Err("quarantine-hard-links".into());
        }
    }
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
fn pending_path(original: &Path, id: &str) -> Result<PathBuf> {
    if !original.is_absolute() || uuid::Uuid::parse_str(id).is_err() {
        return Err("invalid-quarantine-item".into());
    }
    Ok(original.with_file_name(format!(".aegis-quarantine-{id}.pending")))
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
    if std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .is_some_and(|p| p == path)
    {
        return true;
    }
    if path.starts_with(core.dir.canonicalize().unwrap_or(core.dir.clone()))
        || path.starts_with(
            core.resources
                .canonicalize()
                .unwrap_or(core.resources.clone()),
        )
    {
        return true;
    }
    if cfg!(windows) {
        std::env::var_os("SystemRoot").is_some_and(|p| {
            let root = PathBuf::from(p);
            path.starts_with(root.canonicalize().unwrap_or(root))
        })
    } else {
        ["/bin", "/sbin", "/usr", "/lib", "/etc", "/boot", "/System"]
            .iter()
            .any(|p| path.starts_with(p))
    }
}
pub fn pending_files(core: &Core) -> Result<Vec<PathBuf>> {
    let s = core.store.lock().map_err(|_| "state-lock")?;
    Ok(s.data["quarantine"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| item["state"] == "pending")
        .filter_map(|item| {
            pending_path(Path::new(item["original"].as_str()?), item["id"].as_str()?).ok()
        })
        .collect())
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
    if blocked(core, &original)
        || pending_files(core)?
            .iter()
            .any(|p| p.canonicalize().is_ok_and(|p| p == original))
    {
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
    let pending = pending_path(&original, &id)?;
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
    if let Err(error) = fs::rename(&original, &pending) {
        entry["state"] = json!("failed");
        entry["error"] = json!(error.to_string());
        save(core, &entry)?;
        return Err(format!("quarantine-move-failed: {error}"));
    }
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
    let parent = original.parent().ok_or("invalid-quarantine-item")?;
    if parent.canonicalize().map_err(|e| e.to_string())? != parent {
        return Err("quarantine-parent-changed".into());
    }
    if original.try_exists().map_err(|e| e.to_string())? {
        return Err("quarantine-restore-conflict".into());
    }
    let pending = pending_path(&original, id)?;
    let temporary = original.with_file_name(format!(".aegis-restore-{}.tmp", store::id()));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&temporary).map_err(|e| e.to_string())?;
    let result = (|| -> Result<()> {
        if pending.exists() {
            let mut input = open_regular(&pending)?;
            std::io::copy(&mut input, &mut output).map_err(|e| e.to_string())?;
        } else {
            let mut input = fs::File::open(owned(core, id, "aegis")?).map_err(|e| e.to_string())?;
            let mut header = vec![0; HEADER.len()];
            input.read_exact(&mut header).map_err(|e| e.to_string())?;
            if header != HEADER {
                return Err("quarantine-integrity".into());
            }
            let count = std::io::copy(
                &mut DecoderReader::new(input, &STANDARD).take(MAX + 1),
                &mut output,
            )
            .map_err(|e| e.to_string())?;
            if count > MAX {
                return Err("quarantine-integrity".into());
            }
        }
        output.sync_all().map_err(|e| e.to_string())?;
        if hash(&temporary)? != entry["sha256"].as_str().unwrap_or("") {
            return Err("quarantine-integrity".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output
                .set_permissions(fs::Permissions::from_mode(
                    entry["mode"].as_u64().unwrap_or(0o600) as u32 & 0o777,
                ))
                .map_err(|e| e.to_string())?;
        }
        // Hard-linking a completed temporary file publishes it atomically and refuses
        // an existing destination, including one created after the initial check.
        fs::hard_link(&temporary, &original).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                "quarantine-restore-conflict".into()
            } else {
                e.to_string()
            }
        })?;
        Ok(())
    })();
    drop(output);
    let _ = fs::remove_file(&temporary);
    result?;
    #[cfg(windows)]
    if entry["mode"].as_u64() == Some(1) {
        let mut permissions = fs::metadata(&original)
            .map_err(|e| e.to_string())?
            .permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&original, permissions).map_err(|e| e.to_string())?;
    }
    entry["state"] = json!("restored");
    entry["restoredAt"] = json!(store::now());
    save(core, &entry)?;
    let container = owned(core, id, "aegis")?;
    if container.exists() {
        fs::remove_file(container).map_err(|e| e.to_string())?;
    }
    if pending.exists() {
        fs::remove_file(pending).map_err(|e| e.to_string())?;
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
    #[test]
    fn restore_round_trip_checks_hash_and_container_is_not_executable() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let core = Core::new(data.clone(), data.join("engines")).unwrap();
        store::private_dir(&data.join("quarantine")).unwrap();
        let original = root.path().canonicalize().unwrap().join("sample.txt");
        let id = store::id();
        let bytes = b"a harmless quarantine fixture";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let container = owned(&core, &id, "aegis").unwrap();
        store::write_private(
            &container,
            &[HEADER, STANDARD.encode(bytes).as_bytes()].concat(),
            true,
        )
        .unwrap();
        save(
            &core,
            &json!({"id":id,"state":"isolated","original":original,"sha256":digest,"mode":384}),
        )
        .unwrap();
        restore(&core, &id).unwrap();
        assert_eq!(fs::read(&original).unwrap(), bytes);
        assert!(!container.exists());
        assert_eq!(list(&core).unwrap()[0]["state"], "restored");
    }
    #[test]
    fn corrupted_container_is_retained_and_never_published() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let core = Core::new(data.clone(), data.join("engines")).unwrap();
        store::private_dir(&data.join("quarantine")).unwrap();
        let original = root.path().canonicalize().unwrap().join("sample.txt");
        let id = store::id();
        let container = owned(&core, &id, "aegis").unwrap();
        store::write_private(&container, &[HEADER, b"YmFk"].concat(), true).unwrap();
        save(
            &core,
            &json!({"id":id,"state":"isolated","original":original,"sha256":"wrong","mode":384}),
        )
        .unwrap();
        assert!(restore(&core, &id).is_err());
        assert!(!original.exists());
        assert!(container.exists());
    }
}
