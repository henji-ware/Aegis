mod antivirus;
mod audit;
mod firewall;
mod localization;
mod network;
mod platform;
mod privacy;
mod runner;
mod store;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Child,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use store::Result;
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_opener::OpenerExt;
#[derive(Clone)]
pub struct Core {
    pub store: Arc<Mutex<store::Store>>,
    pub resources: PathBuf,
    pub dir: PathBuf,
    pub job: Arc<Mutex<Value>>,
    pub scan_child: Arc<Mutex<Option<Child>>>,
    pub scan_busy: Arc<AtomicBool>,
    pub scan_cancel: Arc<AtomicBool>,
    pub tor: Arc<Mutex<Value>>,
    pub tor_child: Arc<Mutex<Option<Child>>>,
    pub tor_busy: Arc<AtomicBool>,
    pub analysis: Arc<Mutex<HashMap<String, network::Snapshot>>>,
    mutation: Arc<AtomicBool>,
    auditing: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
}
impl Core {
    fn new(dir: PathBuf, resources: PathBuf) -> Result<Self> {
        let store = store::Store::open(dir.clone())?;
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            resources,
            dir,
            job: Arc::new(Mutex::new(Value::Null)),
            scan_child: Arc::new(Mutex::new(None)),
            scan_busy: Arc::new(AtomicBool::new(false)),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            tor: Arc::new(Mutex::new(
                json!({"state":"stopped","progress":0,"port":null,"lines":[]}),
            )),
            tor_child: Arc::new(Mutex::new(None)),
            tor_busy: Arc::new(AtomicBool::new(false)),
            analysis: Arc::new(Mutex::new(HashMap::new())),
            mutation: Arc::new(AtomicBool::new(false)),
            auditing: Arc::new(AtomicBool::new(false)),
            closing: Arc::new(AtomicBool::new(false)),
        })
    }
}
fn confirm(
    app: &tauri::AppHandle,
    core: &Core,
    title: &str,
    message: &str,
    detail: &str,
) -> Result<()> {
    let tx = |s| localization::tx(core, s);
    let message = format!("{}\n\n{}", tx(message), tx(detail));
    let accepted = app
        .dialog()
        .message(message)
        .title(tx(title))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            tx("Continuar"),
            tx("Cancelar"),
        ))
        .blocking_show();
    if accepted {
        Ok(())
    } else {
        Err("cancelled".into())
    }
}
fn selected(
    app: &tauri::AppHandle,
    core: &Core,
    title: &str,
    folder: bool,
) -> Result<Option<PathBuf>> {
    let dialog = app.dialog().file().set_title(localization::tx(core, title));
    let selected = if folder {
        dialog.blocking_pick_folder()
    } else {
        dialog.blocking_pick_file()
    };
    selected
        .map(|p| p.into_path().map_err(|e| e.to_string()))
        .transpose()
}
fn dispatch(core: &Core, app: &tauri::AppHandle, method: &str, payload: Value) -> Result<Value> {
    match method {
        "bootstrap" => {
            let system = platform::system();
            let s = core.store.lock().map_err(|_| "state-lock")?;
            Ok(
                json!({"system":system,"settings":s.data["settings"],"history":s.data["history"],"latestAudit":s.data["audits"][0],"version":env!("CARGO_PKG_VERSION"),"recoveryMessage":s.recovery}),
            )
        }
        "settings" => {
            store::settings(&payload)?;
            let mut s = core.store.lock().map_err(|_| "state-lock")?;
            for (k, v) in payload.as_object().unwrap() {
                s.data["settings"][k] = v.clone();
            }
            s.save()?;
            Ok(s.data["settings"].clone())
        }
        "history" => {
            let s = core.store.lock().map_err(|_| "state-lock")?;
            Ok(
                json!({"events":s.data["history"],"audits":s.data["audits"],"scans":s.data["scans"]}),
            )
        }
        "audit" => {
            if core
                .auditing
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                return Err("audit-running".into());
            }
            let _ = app.emit(
                "aegis:event",
                json!({"type":"audit","data":{"state":"running"}}),
            );
            let result = audit::run(core).and_then(|result| {
                let mut s = core.store.lock().map_err(|_| "state-lock")?;
                s.push("audits", result.clone(), 30)?;
                s.event(
                    "audit",
                    "Diagnóstico concluído",
                    result["counts"].clone(),
                    "success",
                )?;
                Ok(result)
            });
            let _=app.emit("aegis:event",json!({"type":"audit","data":{"state":if result.is_ok(){"completed"}else{"error"},"result":result.as_ref().ok()}}));
            core.auditing.store(false, Ordering::SeqCst);
            result
        }
        "connections" => Ok(json!(platform::connections()?)),
        "connections:analyse" => network::inspect(core),
        "connections:scan" => {
            let token = payload["token"].as_str().ok_or("analysis-expired")?;
            antivirus::start(core, app, "custom", Some(network::resolve(core, token)?))
        }
        "av:status" => antivirus::status(core),
        "av:update" => antivirus::start(core, app, "update", None),
        "av:scan" => {
            let kind = payload["type"].as_str().ok_or("invalid-scan-type")?;
            let path = if kind == "custom" {
                let folder = payload["selection"] == "folder";
                match selected(app, core, "Escolha o que deseja verificar", folder)? {
                    Some(path) => Some(path),
                    None => return Ok(Value::Null),
                }
            } else {
                None
            };
            antivirus::start(core, app, kind, path)
        }
        "av:cancel" => {
            core.scan_cancel.store(true, Ordering::SeqCst);
            if let Ok(mut job) = core.job.lock() {
                if job["state"] == "running" {
                    job["state"] = json!("cancelling");
                }
            }
            Ok(json!(true))
        }
        "firewall:status" => firewall::status(core),
        "firewall:harden" => {
            confirm(
                app,
                core,
                "Reforçar firewall",
                "Ativar o firewall e restringir novas conexões de entrada?",
                if cfg!(windows) {
                    "Ativa os perfis Domínio, Privado e Público e define o padrão de entrada como Bloquear. As regras existentes continuam válidas. A configuração local anterior será salva para restauração."
                } else if cfg!(target_os = "macos") {
                    "Ativa o firewall de aplicações e o modo discreto. A configuração anterior será salva."
                } else {
                    "Define o padrão de entrada do UFW como Negar e ativa o firewall. Isso pode interromper acesso remoto e serviços. As regras existentes permanecem."
                },
            )?;
            firewall::harden(core)
        }
        "firewall:restore" => {
            confirm(app,core,"Restaurar firewall","Restaurar a configuração anterior ao reforço?","As opções modificadas pelo reforço voltarão aos valores salvos. Regras de outros aplicativos serão preservadas.")?;
            firewall::restore(core)
        }
        "firewall:block" => {
            let port = firewall::port(&payload["port"])?;
            confirm(
                app,
                core,
                "Bloquear porta",
                &localization::tx(
                    core,
                    "Bloquear novas conexões TCP de entrada na porta {port}?",
                )
                .replace("{port}", &port.to_string()),
                "A regra será identificada como Aegis e poderá ser removida pelo aplicativo.",
            )?;
            firewall::block(core, &json!(port))
        }
        "firewall:remove" => {
            let id = payload["id"].as_str().ok_or("invalid-rule")?;
            confirm(app,core,"Remover regra","Remover esta regra de bloqueio do Aegis?","Conexões antes bloqueadas por esta regra poderão ser permitidas por outras políticas.")?;
            firewall::remove(core, id)
        }
        "vpn:status" => privacy::vpn_status(core),
        "vpn:import" => {
            let file = app
                .dialog()
                .file()
                .set_title(localization::tx(core, "Importar perfil WireGuard"))
                .add_filter("WireGuard", &["conf"])
                .blocking_pick_file();
            match file {
                Some(file) => privacy::import(core, &file.into_path().map_err(|e| e.to_string())?),
                None => Ok(Value::Null),
            }
        }
        "vpn:connect" => {
            confirm(app,core,"Conectar VPN","Ativar este perfil WireGuard?","O perfil pode alterar rotas e servidores DNS. Use somente configurações de um servidor em que você confia. Uma interface ativa, por si só, não confirma ausência de vazamentos. O túnel permanece ativo ao fechar o Aegis; desconecte-o aqui antes de sair se necessário.")?;
            privacy::connect(core, payload["id"].as_str().ok_or("invalid-profile")?)
        }
        "vpn:disconnect" => {
            confirm(
                app,
                core,
                "Desconectar VPN",
                "Desconectar o túnel gerenciado pelo Aegis?",
                "As conexões voltarão a seguir as rotas do sistema.",
            )?;
            privacy::disconnect(core)
        }
        "vpn:remove" => {
            confirm(
                app,
                core,
                "Remover perfil",
                "Remover este perfil VPN do cofre local?",
                "A configuração importada originalmente não será alterada.",
            )?;
            privacy::remove(core, payload["id"].as_str().ok_or("invalid-profile")?)
        }
        "tor:status" => privacy::tor_status(core),
        "tor:start" => privacy::start_tor(core, app),
        "tor:stop" => privacy::stop_tor(core, app),
        "export" => {
            let file = app
                .dialog()
                .file()
                .set_title(localization::tx(core, "Exportar relatório local"))
                .set_file_name(format!(
                    "Aegis-report-{}.html",
                    chrono::Utc::now().format("%Y-%m-%d")
                ))
                .add_filter("HTML", &["html"])
                .blocking_save_file();
            if let Some(file) = file {
                let path = file.into_path().map_err(|e| e.to_string())?;
                let html = localization::report(core)?;
                store::write_private(&path, html.as_bytes(), false)?;
                core.store.lock().map_err(|_| "state-lock")?.event(
                    "report",
                    "Relatório exportado",
                    json!("Arquivo HTML salvo no local escolhido."),
                    "success",
                )?;
                Ok(json!(path))
            } else {
                Ok(Value::Null)
            }
        }
        "external" => {
            let url = match payload["id"].as_str() {
                Some("clamav") => "https://www.clamav.net/",
                Some("clamavDocs") => "https://docs.clamav.net/manual/Usage/Scanning.html",
                Some("tor") => "https://www.torproject.org/download/",
                Some("torDocs") => "https://support.torproject.org/",
                Some("wireguard") => "https://www.wireguard.com/install/",
                Some("portmaster") => "https://safing.io/portmaster/",
                Some("lulu") => "https://objective-see.org/products/lulu.html",
                Some("sourceClam") => "https://github.com/Cisco-Talos/clamav",
                Some("sourceTor") => "https://gitlab.torproject.org/tpo/core/tor",
                Some("sourceWireguard") => "https://git.zx2c4.com/wireguard-windows/",
                _ => return Err("invalid-destination".into()),
            };
            app.opener()
                .open_url(url, None::<&str>)
                .map_err(|e| e.to_string())?;
            Ok(json!(true))
        }
        _ => Err("operation-not-allowed".into()),
    }
}
#[tauri::command]
async fn aegis_call(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Core>,
    method: String,
    payload: Option<Value>,
) -> std::result::Result<Value, Value> {
    if window.label() != "main" {
        return Err(localization::error("unauthorized-origin"));
    }
    let url = window
        .url()
        .map_err(|e| localization::error(&e.to_string()))?;
    let local = url.scheme() == "tauri" && url.host_str() == Some("localhost")
        || url.scheme() == "http" && url.host_str() == Some("tauri.localhost");
    let dev = cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(5173);
    if !(local || dev)
        || method.len() > 64
        || payload
            .as_ref()
            .is_some_and(|p| p.to_string().len() > 10000)
    {
        return Err(localization::error("operation-not-allowed"));
    }
    let core = state.inner().clone();
    let app = window.app_handle().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mutation = matches!(
            method.as_str(),
            "firewall:harden"
                | "firewall:restore"
                | "firewall:block"
                | "firewall:remove"
                | "vpn:import"
                | "vpn:connect"
                | "vpn:disconnect"
                | "vpn:remove"
        );
        if mutation
            && core
                .mutation
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return Err(localization::error("operation-busy"));
        }
        let result = dispatch(&core, &app, &method, payload.unwrap_or(Value::Null));
        if mutation {
            core.mutation.store(false, Ordering::SeqCst);
        }
        result.map_err(|e| localization::error(&e))
    })
    .await
    .map_err(|e| localization::error(&e.to_string()))?
}
fn migrate(core: &Core) {
    if core.dir.join("migration-checked").exists() {
        return;
    }
    let old = if cfg!(windows) {
        std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("Aegis"))
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|p| PathBuf::from(p).join("Library/Application Support/Aegis"))
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
            .map(|p| p.join("Aegis"))
    };
    if let Some(old) = old {
        if old != core.dir {
            if let Ok(text) = store::read_limited(&old.join("state.json"), 32 * 1024 * 1024) {
                if let Ok(data) = serde_json::from_str::<Value>(&text) {
                    if data["version"] == 1 {
                        let _ = store::write_private(
                            &core.dir.join("legacy-electron-state.json"),
                            text.as_bytes(),
                            true,
                        );
                        if let Ok(mut s) = core.store.lock() {
                            if s.data["history"].as_array().is_some_and(|a| a.is_empty()) {
                                for field in
                                    ["history", "audits", "scans", "rules", "firewallBackup"]
                                {
                                    if !data[field].is_null() {
                                        s.data[field] = data[field].clone();
                                    }
                                }
                                if store::settings(&data["settings"]).is_ok() {
                                    s.data["settings"] = data["settings"].clone();
                                }
                                if let Some(tunnel) =
                                    data["activeVpn"]["tunnel"].as_str().filter(|t| {
                                        regex::Regex::new("^ag[a-f0-9]{10}$").unwrap().is_match(t)
                                    })
                                {
                                    let name = format!(
                                        "{tunnel}.conf{}",
                                        if cfg!(windows) { ".dpapi" } else { "" }
                                    );
                                    let old_file = old.join("tunnels").join(&name);
                                    let new_dir = core.dir.join("tunnels");
                                    let _ = store::private_dir(&new_dir);
                                    if let Ok(bytes) = std::fs::read(old_file) {
                                        if bytes.len() <= 131072 {
                                            let _ = store::write_private(
                                                &new_dir.join(&name),
                                                &bytes,
                                                true,
                                            );
                                        }
                                    }
                                    s.data["activeVpn"] = data["activeVpn"].clone();
                                    s.data["activeVpn"]["pending"] = json!(true);
                                }
                                s.recovery=Some("Migração concluída. Reimporte os perfis VPN no novo cofre; os dados anteriores foram preservados.".into());
                                let _ = s.save();
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = store::write_private(&core.dir.join("migration-checked"), b"1", true);
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let application=tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app,_,_|{if let Some(window)=app.get_webview_window("main"){let _=window.show();let _=window.set_focus();}})).plugin(tauri_plugin_dialog::init()).plugin(tauri_plugin_opener::init()).setup(|app|{let mut dir=app.path().app_data_dir()?;let mut resources=app.path().resource_dir()?.join("engines");#[cfg(debug_assertions)]{if let Some(path)=std::env::var_os("AEGIS_DATA_DIR"){dir=PathBuf::from(path);}resources=Path::new(env!("CARGO_MANIFEST_DIR")).join("../resources");}let core=Core::new(dir,resources).map_err(std::io::Error::other)?;migrate(&core);app.manage(core);Ok(())}).invoke_handler(tauri::generate_handler![aegis_call]).on_window_event(|window,event|{if let tauri::WindowEvent::CloseRequested{api,..}=event{let core=window.state::<Core>().inner().clone();if core.closing.swap(true,Ordering::SeqCst){api.prevent_close();return;}api.prevent_close();let app=window.app_handle().clone();std::thread::spawn(move||{if core.scan_busy.load(Ordering::SeqCst)&&confirm(&app,&core,"Há uma tarefa do antivírus em andamento.","Sair interrompe a tarefa. O resultado não será considerado uma varredura concluída.","").is_err(){core.closing.store(false,Ordering::SeqCst);return;}core.scan_cancel.store(true,Ordering::SeqCst);let _=privacy::stop_tor(&core,&app);for _ in 0..80{if !core.scan_busy.load(Ordering::SeqCst){break;}std::thread::sleep(std::time::Duration::from_millis(100));}app.exit(0);});}}).build(tauri::generate_context!()).expect("Unable to initialize Aegis");
    application.run(|app, event| {
        if let tauri::RunEvent::Exit = event {
            let core = app.state::<Core>();
            core.scan_cancel.store(true, Ordering::SeqCst);
            if let Ok(mut slot) = core.tor_child.lock() {
                if let Some(child) = slot.as_mut() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            if let Ok(mut slot) = core.scan_child.lock() {
                if let Some(child) = slot.as_mut() {
                    let _ = child.kill();
                }
            };
        }
    });
}
#[cfg(test)]
mod native_tests {
    use super::*;
    #[test]
    fn interrupted_scan_remains_in_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store::Store::open(dir.path().into()).unwrap();
        s.data["activeScan"] = json!({"id":"pending","state":"running","type":"custom","startedAt":store::now(),"lines":[],"summary":{"infected":1,"threats":[{"path":"test","name":"test"}]}});
        s.save().unwrap();
        drop(s);
        let restored = store::Store::open(dir.path().into()).unwrap();
        assert!(restored.data["activeScan"].is_null());
        assert_eq!(restored.data["scans"][0]["state"], "interrupted");
        assert_eq!(restored.data["scans"][0]["summary"]["infected"], 1);
    }
    #[test]
    fn native_engines_and_read_only_queries() {
        let Some(dir) = std::env::var_os("AEGIS_NATIVE_TEST_RESOURCES") else {
            return;
        };
        let resources = PathBuf::from(dir).canonicalize().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let core = Core::new(temporary.path().to_path_buf(), resources).unwrap();
        let scanner =
            runner::engine(&core.resources, "clamav", "clamscan").expect("ClamAV must be bundled");
        let version = runner::capture(
            &scanner,
            &["--version".into()],
            20,
            None,
            &runner::runtime_env(&core.resources, "clamav"),
        )
        .unwrap();
        assert_eq!(version.code, 0);
        assert!(version.text.contains("ClamAV"));
        let tor = runner::engine(&core.resources, "tor", "tor").expect("Tor must be bundled");
        assert_eq!(
            runner::capture(
                &tor,
                &["--version".into()],
                20,
                None,
                &runner::runtime_env(&core.resources, "tor")
            )
            .unwrap()
            .code,
            0
        );
        let fixture = temporary.path().join("clean-fixture.txt");
        std::fs::write(&fixture, "aegis-native-test-fixture").unwrap();
        let db = temporary.path().join("fixture.ndb");
        std::fs::write(
            &db,
            "Aegis.Native.Test:0:*:61656769732d6e61746976652d746573742d66697874757265\n",
        )
        .unwrap();
        let output = runner::capture(
            &scanner,
            &[
                format!("--database={}", db.display()),
                "--infected".into(),
                "--stdout".into(),
                "--".into(),
                fixture.to_string_lossy().into_owned(),
            ],
            30,
            None,
            &runner::runtime_env(&core.resources, "clamav"),
        )
        .unwrap();
        assert_eq!(output.code, 1, "{}", output.text);
        let mut parsed = antivirus::ScanOutput::default();
        for line in output.text.lines() {
            parsed.accept(line);
        }
        assert_eq!(parsed.result(output.code)["infected"], 1);
        assert_eq!(parsed.result(output.code)["state"], "threats");
        assert!(platform::system()["memory"].as_u64().unwrap() > 0);
        let rows = platform::connections().expect("native TCP enumeration");
        for r in rows {
            assert_eq!(r["protocol"], "TCP");
        }
        let _ = platform::guard();
    }
}
