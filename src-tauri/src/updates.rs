use crate::{privacy, store::Result, Core};
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::Emitter;
use tauri_plugin_updater::UpdaterExt;

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use minisign_verify::{PublicKey, Signature};
    use std::{fs, path::Path};
    #[test]
    fn updater_package_signatures() {
        if std::env::var("AEGIS_VERIFY_UPDATER_ARTIFACTS").as_deref() != Ok("true") {
            return;
        }
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let config: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(root.join("tauri.conf.json")).unwrap())
                .unwrap();
        let public = String::from_utf8(
            STANDARD
                .decode(config["plugins"]["updater"]["pubkey"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        let key = PublicKey::decode(&public).unwrap();
        let mut signatures = vec![];
        fn walk(path: &Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in fs::read_dir(path).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    walk(&p, found);
                } else if p.extension().is_some_and(|s| s == "sig") {
                    found.push(p);
                }
            }
        }
        walk(&root.join("target/release/bundle"), &mut signatures);
        assert!(
            signatures.len() >= if cfg!(windows) { 2 } else { 1 },
            "Missing signed updater artifacts"
        );
        for path in signatures {
            let sig = String::from_utf8(
                STANDARD
                    .decode(fs::read_to_string(&path).unwrap().trim())
                    .unwrap(),
            )
            .unwrap();
            let sig = Signature::decode(&sig).unwrap();
            assert!(
                sig.trusted_comment()
                    .split('\t')
                    .any(|f| f == format!("version:{}", env!("CARGO_PKG_VERSION"))),
                "Updater signature must bind the app version"
            );
            let package = path.with_file_name(
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .trim_end_matches(".sig"),
            );
            let mut bytes = fs::read(&package).unwrap();
            key.verify(&bytes, &sig, true)
                .expect("Updater artifact must match the embedded public key");
            assert!(!bytes.is_empty());
            bytes[0] ^= 1;
            assert!(
                key.verify(&bytes, &sig, true).is_err(),
                "Tampered updater artifact was accepted"
            );
        }
    }
}
pub fn check(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
    let portable = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.join("aegis-portable.json")))
        .is_some_and(|p| p.is_file());
    if portable || cfg!(target_os = "linux") && std::env::var_os("APPIMAGE").is_none() {
        return Ok(
            json!({"available":false,"supported":false,"manual":if portable{"portable"}else{"package"}}),
        );
    }
    let update = tauri::async_runtime::block_on(
        app.updater_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?
            .check(),
    )
    .map_err(|e| e.to_string())?;
    if let Some(u) = &update {
        if u.download_url.scheme() != "https"
            || u.download_url.host_str() != Some("github.com")
            || !u
                .download_url
                .path()
                .starts_with("/henji-ware/Aegis/releases/download/")
        {
            return Err("update-untrusted-origin".into());
        }
    }
    let result=update.as_ref().map(|u|json!({"available":true,"version":u.version,"notes":u.body,"checkedAt":crate::store::now()})).unwrap_or(json!({"available":false,"version":env!("CARGO_PKG_VERSION"),"checkedAt":crate::store::now()}));
    *core.update.lock().map_err(|_| "update-lock")? = update;
    let _ = app.emit("aegis:event", json!({"type":"update","data":result}));
    Ok(result)
}
pub fn install(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
    if core
        .scan_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("antivirus-busy".into());
    }
    let result = (|| {
        let update = core
            .update
            .lock()
            .map_err(|_| "update-lock")?
            .clone()
            .ok_or("update-check-required")?;
        let mut downloaded = 0u64;
        let bytes=tauri::async_runtime::block_on(update.download(|count,total|{downloaded+=count as u64;let _=app.emit("aegis:event",json!({"type":"update","data":{"available":true,"version":update.version,"phase":"download","downloaded":downloaded,"total":total,"percent":total.filter(|n|*n>0).map(|n|(downloaded*100/n).min(100))}}));},||{})).map_err(|e|e.to_string())?;
        // The plugin verifies Minisign before returning any installable bytes.
        privacy::stop_tor(core, app)?;
        let _ = app.emit(
            "aegis:event",
            json!({"type":"update","data":{"phase":"install","version":update.version}}),
        );
        update.install(bytes).map_err(|e| e.to_string())?;
        app.restart();
        #[allow(unreachable_code)]
        Ok(json!(true))
    })();
    core.scan_busy.store(false, Ordering::SeqCst);
    result
}
