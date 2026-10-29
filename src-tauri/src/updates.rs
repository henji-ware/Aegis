use crate::{privacy, store::Result, Core};
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};
use tauri::Emitter;
use tauri_plugin_updater::UpdaterExt;
pub fn check(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
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
