use crate::{
    runner::*,
    store::{self, Result},
    Core,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, Read},
    net::{IpAddr, TcpListener},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    thread,
    time::Duration,
};
use tauri::Emitter;
use zeroize::Zeroizing;
pub fn profile(text: &str) -> Result<(String, Value)> {
    if text.len() > 65536 {
        return Err("invalid-vpn-profile".into());
    }
    let (mut section, mut interfaces, mut peers, mut peer_key, mut private) =
        ("", 0, 0, false, false);
    let mut keys = HashSet::new();
    let mut clean = vec![];
    let mut addresses = vec![];
    let mut dns = vec![];
    let (mut endpoint, mut full, mut ipv6) = (String::new(), false, false);
    for raw in text.trim_start_matches('\u{feff}').lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if ["[Interface]", "[Peer]"].contains(&line) {
            if section == "Peer" && !peer_key {
                return Err("invalid-vpn-profile".into());
            }
            section = &line[1..line.len() - 1];
            keys.clear();
            if section == "Interface" {
                interfaces += 1;
                if interfaces != 1 || peers > 0 {
                    return Err("invalid-vpn-profile".into());
                }
            } else {
                peers += 1;
                peer_key = false;
                if interfaces != 1 || peers > 16 {
                    return Err("invalid-vpn-profile".into());
                }
            }
            clean.push(line.to_string());
            continue;
        }
        let (key, value) = line.split_once('=').ok_or("invalid-vpn-profile")?;
        let key = key.trim();
        let value = value.trim();
        let allowed = match section {
            "Interface" => ["PrivateKey", "Address", "DNS", "ListenPort", "MTU"].contains(&key),
            "Peer" => [
                "PublicKey",
                "PresharedKey",
                "AllowedIPs",
                "Endpoint",
                "PersistentKeepalive",
            ]
            .contains(&key),
            _ => false,
        };
        if !allowed
            || !keys.insert(key.to_string())
            || value.is_empty()
            || value.contains(['\0', '\r', '\n'])
        {
            return Err("invalid-vpn-profile".into());
        }
        match key {
            "PrivateKey" | "PublicKey" | "PresharedKey" => {
                if STANDARD.decode(value).map(|b| b.len()).ok() != Some(32) {
                    return Err("invalid-vpn-profile".into());
                }
                if key == "PrivateKey" {
                    private = true;
                }
                if key == "PublicKey" {
                    peer_key = true;
                }
            }
            "Address" | "AllowedIPs" => {
                for cidr in value.split(',').map(str::trim) {
                    let (ip, bits) = cidr.split_once('/').ok_or("invalid-vpn-profile")?;
                    let ip: IpAddr = ip.parse().map_err(|_| "invalid-vpn-profile")?;
                    let bits: u8 = bits.parse().map_err(|_| "invalid-vpn-profile")?;
                    if bits > if ip.is_ipv4() { 32 } else { 128 } {
                        return Err("invalid-vpn-profile".into());
                    }
                    if key == "Address" {
                        addresses.push(cidr.to_string());
                    } else {
                        full |= cidr == "0.0.0.0/0";
                        ipv6 |= cidr == "::/0";
                    }
                }
            }
            "DNS" => {
                for server in value.split(',').map(str::trim) {
                    server
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid-vpn-profile")?;
                    dns.push(server.to_string());
                }
            }
            "Endpoint" => {
                let (host, port) = value.rsplit_once(':').ok_or("invalid-vpn-profile")?;
                let port: u16 = port.parse().map_err(|_| "invalid-vpn-profile")?;
                if port == 0 || host.is_empty() {
                    return Err("invalid-vpn-profile".into());
                }
                if host.starts_with('[') {
                    host.trim_matches(['[', ']'])
                        .parse::<std::net::Ipv6Addr>()
                        .map_err(|_| "invalid-vpn-profile")?;
                } else if !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                    || !host.chars().next().unwrap().is_ascii_alphanumeric()
                {
                    return Err("invalid-vpn-profile".into());
                }
                endpoint = value.into();
            }
            _ => {
                value.parse::<u16>().map_err(|_| "invalid-vpn-profile")?;
            }
        }
        clean.push(format!("{key} = {value}"));
    }
    if !private || peers == 0 || !peer_key || addresses.is_empty() {
        return Err("invalid-vpn-profile".into());
    }
    Ok((
        clean.join("\n") + "\n",
        json!({"endpoint":endpoint,"addresses":addresses,"dns":dns,"fullTunnel":full,"ipv6":ipv6,"peers":peers,"nativeKillSwitch":peers==1&&(full||ipv6)}),
    ))
}
fn credential(id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new("org.aegis.desktop", id).map_err(|e| e.to_string())
}
pub fn secure() -> bool {
    let value = store::id();
    credential("storage-probe")
        .and_then(|entry| {
            entry.set_password(&value).map_err(|e| e.to_string())?;
            let read = entry.get_password().map_err(|e| e.to_string());
            let _ = entry.delete_credential();
            read
        })
        .is_ok_and(|s| s == value)
}
fn wg(core: &Core) -> Option<PathBuf> {
    if cfg!(windows) {
        let dir = PathBuf::from(
            std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
        )
        .join("WireGuard/wireguard.exe");
        tool(
            "wireguard",
            &[core.resources.join("wireguard/wireguard.exe"), dir],
        )
    } else {
        tool("wg-quick", &[])
    }
}
fn tunnel(active: &Value) -> Result<&str> {
    let t = active["tunnel"].as_str().ok_or("invalid-owned-tunnel")?;
    if !regex::Regex::new("^ag[a-f0-9]{10}$").unwrap().is_match(t) {
        return Err("invalid-owned-tunnel".into());
    }
    Ok(t)
}
fn file(core: &Core, active: &Value) -> Result<PathBuf> {
    let t = tunnel(active)?;
    Ok(core.dir.join("tunnels").join(format!(
        "{t}.conf{}",
        if cfg!(windows) { ".dpapi" } else { "" }
    )))
}
pub fn observe(active: &Value) -> Value {
    let result = (|| -> Result<Value> {
        let t = tunnel(active)?;
        if cfg!(windows) {
            return ps_json(&format!("try {{$s=Get-Service -Name {} -ErrorAction Stop; [pscustomobject]@{{present=$true;interfaceActive=($s.Status -eq 'Running');interfaceName={}}} | ConvertTo-Json -Compress}}catch{{if($_.FullyQualifiedErrorId -match '^NoServiceFoundForGivenName'){{'{{\"present\":false,\"interfaceActive\":false}}'}}else{{throw}}}}",quote(&format!("WireGuardTunnel${t}")),quote(t)));
        }
        let name = if cfg!(target_os = "macos") {
            let map = PathBuf::from(format!("/var/run/wireguard/{t}.name"));
            if !map.exists() {
                return Ok(json!({"present":false,"interfaceActive":false}));
            }
            let name = fs::read_to_string(&map)
                .map_err(|e| e.to_string())?
                .trim()
                .to_string();
            if !regex::Regex::new("^utun[0-9]{1,6}$")
                .unwrap()
                .is_match(&name)
            {
                return Err("invalid-owned-tunnel".into());
            }
            name
        } else {
            t.to_string()
        };
        let interfaces = sysinfo::Networks::new_with_refreshed_list();
        if interfaces.is_empty() {
            return Err("network-status-unavailable".into());
        }
        let found = interfaces.iter().find(|(interface, _)| *interface == &name);
        let present = found.is_some();
        let active = found.is_some_and(|(_, data)| !data.ip_networks().is_empty());
        Ok(json!({"present":present,"interfaceActive":active,"interfaceName":name}))
    })();
    result.unwrap_or_else(|e| json!({"present":null,"interfaceActive":null,"error":e}))
}
pub fn vpn_status(core: &Core) -> Result<Value> {
    let (profiles, mut active) = {
        let s = core.store.lock().map_err(|_| "state-lock")?;
        (s.data["profiles"].clone(), s.data["activeVpn"].clone())
    };
    if !active.is_null() {
        let observed = observe(&active);
        for (k, v) in observed.as_object().unwrap() {
            active[k] = v.clone();
        }
    }
    Ok(
        json!({"installed":wg(core).is_some(),"secureStorage":secure(),"profiles":profiles,"active":active,"verification":"A interface ativa não confirma handshake recente, rotas, DNS ou ausência de vazamentos."}),
    )
}
pub fn import(core: &Core, path: &Path) -> Result<Value> {
    if !secure() {
        return Err("secure-storage-unavailable".into());
    }
    let text = Zeroizing::new(store::read_limited(path, 65536)?);
    let (clean, meta) = profile(&text)?;
    let clean = Zeroizing::new(clean);
    let id = store::id();
    let entry = credential(&id)?;
    entry.set_password(&clean).map_err(|e| e.to_string())?;
    let name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .filter(|c| c.is_alphanumeric() || " _.-".contains(*c))
        .take(48)
        .collect::<String>();
    let item =
        json!({"id":id,"name":if name.is_empty(){"VPN"}else{&name},"meta":meta,"at":store::now()});
    let saved = (|| {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["profiles"]
            .as_array_mut()
            .unwrap()
            .push(item.clone());
        s.event("vpn", "Perfil VPN importado", json!(name), "success")
    })();
    if let Err(error) = saved {
        let _ = entry.delete_credential();
        return Err(error);
    }
    Ok(item)
}
#[cfg(windows)]
fn protect(text: &str, name: &str) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CRYPT_INTEGER_BLOB,
        },
    };
    let mut bytes = Zeroizing::new(text.as_bytes().to_vec());
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let description = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    if unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}
fn run_wg(client: &Path, args: &[String]) -> Result<String> {
    if cfg!(windows) {
        elevated_ps(&format!(
            "& {} {}; if($LASTEXITCODE -ne 0){{throw 'WireGuard failed'}}",
            quote(&client.to_string_lossy()),
            args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
        ))
    } else if cfg!(target_os = "macos") {
        let mut all = vec![
            "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
            client.to_string_lossy().into_owned(),
        ];
        all.extend(args.iter().cloned());
        elevate(Path::new("/usr/bin/env"), &all)
    } else {
        elevate(client, args)
    }
}
pub fn connect(core: &Core, id: &str) -> Result<Value> {
    let item = {
        let s = core.store.lock().map_err(|_| "state-lock")?;
        if !s.data["activeVpn"].is_null() {
            return Err("vpn-already-active".into());
        }
        s.data["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .cloned()
            .ok_or("profile-not-found")?
    };
    let client = wg(core).ok_or("wireguard-required")?;
    let secret = Zeroizing::new(credential(id)?.get_password().map_err(|e| e.to_string())?);
    let (clean, _) = profile(&secret)?;
    let clean = Zeroizing::new(clean);
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| "invalid-profile")?;
    let tunnel = format!("ag{}", &uuid.simple().to_string()[..10]);
    let active = json!({"id":id,"name":item["name"],"tunnel":tunnel,"startedAt":store::now(),"pending":true});
    let path = file(core, &active)?;
    store::private_dir(path.parent().unwrap())?;
    #[cfg(windows)]
    {
        store::write_private(&path, &protect(&clean, &tunnel)?, true)?;
    }
    #[cfg(not(windows))]
    {
        store::write_private(&path, clean.as_bytes(), true)?;
    }
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["activeVpn"] = active.clone();
        if let Err(error) = s.save() {
            let _ = fs::remove_file(&path);
            s.data["activeVpn"] = Value::Null;
            return Err(error);
        }
    }
    let applied = run_wg(
        &client,
        &if cfg!(windows) {
            vec![
                "/installtunnelservice".into(),
                path.to_string_lossy().into_owned(),
            ]
        } else {
            vec!["up".into(), path.to_string_lossy().into_owned()]
        },
    );
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        if applied.is_err() {
            if observe(&active)["present"] == false {
                let _ = fs::remove_file(&path);
                s.data["activeVpn"] = Value::Null;
            } else {
                s.data["activeVpn"]["error"] = json!("vpn-activation-unconfirmed");
            }
            s.save()?;
        } else {
            s.data["activeVpn"]["pending"] = json!(false);
            s.event(
                "vpn",
                "Ativação VPN solicitada",
                item["name"].clone(),
                "info",
            )?;
        }
    }
    applied?;
    vpn_status(core)
}
pub fn disconnect(core: &Core) -> Result<Value> {
    let active = core.store.lock().map_err(|_| "state-lock")?.data["activeVpn"].clone();
    if active.is_null() {
        return Err("vpn-not-active".into());
    }
    let path = file(core, &active)?;
    if observe(&active)["present"] != false {
        let client = wg(core).ok_or("wireguard-required")?;
        run_wg(
            &client,
            &if cfg!(windows) {
                vec!["/uninstalltunnelservice".into(), tunnel(&active)?.into()]
            } else {
                vec!["down".into(), path.to_string_lossy().into_owned()]
            },
        )?;
        if observe(&active)["present"] != false {
            return Err("vpn-removal-unconfirmed".into());
        }
    }
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    let mut s = core.store.lock().map_err(|_| "state-lock")?;
    s.data["activeVpn"] = Value::Null;
    s.event(
        "vpn",
        "Túnel VPN removido",
        active["name"].clone(),
        "success",
    )?;
    drop(s);
    vpn_status(core)
}
pub fn remove(core: &Core, id: &str) -> Result<Value> {
    let mut s = core.store.lock().map_err(|_| "state-lock")?;
    if s.data["activeVpn"]["id"] == id {
        return Err("vpn-already-active".into());
    }
    if !s.data["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["id"] == id)
    {
        return Err("profile-not-found".into());
    }
    credential(id)?
        .delete_credential()
        .map_err(|e| e.to_string())?;
    s.data["profiles"]
        .as_array_mut()
        .unwrap()
        .retain(|p| p["id"] != id);
    s.save()?;
    Ok(json!(true))
}
pub fn tor_status(core: &Core) -> Result<Value> {
    let mut value = core.tor.lock().map_err(|_| "tor-lock")?.clone();
    value["installed"] = json!(engine(&core.resources, "tor", "tor").is_some());
    Ok(value)
}
fn reserve_tor(core: &Core) -> Result<()> {
    // Stop and start must share this lock: a stop request cannot be overwritten
    // between reserving the task and clearing the preceding task's cancel flag.
    let _slot = core.tor_child.lock().map_err(|_| "process-lock")?;
    if core.closing.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    if core
        .tor_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("tor-already-running".into());
    }
    core.tor_cancel.store(false, Ordering::SeqCst);
    Ok(())
}
pub fn start_tor(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
    reserve_tor(core)?;
    let result = start_tor_inner(core, app);
    if result.is_err() && core.tor_child.lock().map(|s| s.is_none()).unwrap_or(false) {
        core.tor_busy.store(false, Ordering::SeqCst);
    }
    result
}
fn start_tor_inner(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
    let binary = engine(&core.resources, "tor", "tor").ok_or("tor-unavailable")?;
    let dir = core.dir.join("tor");
    store::private_dir(&dir)?;
    let config = dir.join("torrc");
    store::write_private(&config, b"# Aegis isolated configuration\n", false)?;
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    drop(listener);
    let mut args = vec![
        "-f".into(),
        config.to_string_lossy().into_owned(),
        "--DataDirectory".into(),
        dir.to_string_lossy().into_owned(),
        "--SocksPort".into(),
        format!("127.0.0.1:{port}"),
        "--ClientOnly".into(),
        "1".into(),
        "--AvoidDiskWrites".into(),
        "1".into(),
        "--Log".into(),
        "notice stdout".into(),
    ];
    for (name, flag) in [("geoip", "--GeoIPFile"), ("geoip6", "--GeoIPv6File")] {
        let p = core.resources.join("tor/data").join(name);
        if p.is_file() {
            args.extend([flag.into(), p.to_string_lossy().into_owned()]);
        }
    }
    let mut cmd = command(&binary, &args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in runtime_env(&core.resources, "tor") {
        cmd.env(k, v);
    }
    let mut slot = core.tor_child.lock().map_err(|_| "process-lock")?;
    if core.tor_cancel.load(Ordering::SeqCst) || core.closing.load(Ordering::SeqCst) {
        return Err("cancelled".into());
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("missing-process-output")?;
    let stderr = child.stderr.take().ok_or("missing-process-output")?;
    *slot = Some(child);
    drop(slot);
    let value = json!({"state":"starting","progress":0,"port":port,"lines":[],"installed":true});
    *core.tor.lock().map_err(|_| "tor-lock")? = value.clone();
    for pipe in [Box::new(stdout) as Box<dyn Read + Send>, Box::new(stderr)] {
        let state = core.clone();
        let handle = app.clone();
        thread::spawn(move || {
            let progress = regex::Regex::new(r"Bootstrapped (\d+)%").unwrap();
            let mut reader = BufReader::new(pipe);
            loop {
                let mut bytes = vec![];
                let mut limited = reader.by_ref().take(65536);
                if !matches!(limited.read_until(b'\n',&mut bytes),Ok(n)if n>0) {
                    break;
                }
                let line = String::from_utf8_lossy(&bytes)
                    .trim()
                    .chars()
                    .take(1500)
                    .collect::<String>();
                if let Ok(mut tor) = state.tor.lock() {
                    if tor["state"] == "stopped" {
                        break;
                    }
                    if let Some(c) = progress.captures(&line) {
                        let n = c[1].parse::<u8>().unwrap_or(0);
                        tor["progress"] = json!(n);
                        if n == 100 {
                            tor["state"] = json!("ready");
                        }
                    }
                    let lines = tor["lines"].as_array_mut().unwrap();
                    lines.push(json!(line));
                    if lines.len() > 30 {
                        lines.remove(0);
                    }
                    let _ = handle.emit("aegis:event", json!({"type":"tor","data":tor.clone()}));
                }
            }
        });
    }
    let state = core.clone();
    let handle = app.clone();
    thread::spawn(move || {
        let exit = loop {
            let status = state
                .tor_child
                .lock()
                .ok()
                .and_then(|mut slot| slot.as_mut().and_then(|c| c.try_wait().ok().flatten()));
            if let Some(status) = status {
                break status.code().unwrap_or(-1);
            }
            thread::sleep(Duration::from_millis(200));
        };
        if let Ok(mut tor) = state.tor.lock() {
            if tor["state"] != "stopped" {
                tor["state"] = json!(if exit == 0 { "stopped" } else { "error" });
                if exit != 0 {
                    tor["error"] = json!("tor-exited");
                }
            }
            let _ = handle.emit("aegis:event", json!({"type":"tor","data":tor.clone()}));
        }
        if let Ok(mut slot) = state.tor_child.lock() {
            *slot = None;
        }
        state.tor_busy.store(false, Ordering::SeqCst);
    });
    core.store.lock().map_err(|_| "state-lock")?.event(
        "tor",
        "Conexão Tor iniciada",
        json!("Proxy SOCKS local. Apenas aplicativos configurados usam este proxy."),
        "info",
    )?;
    Ok(value)
}
fn cancel_tor(core: &Core) -> Result<()> {
    let mut slot = core.tor_child.lock().map_err(|_| "process-lock")?;
    core.tor_cancel.store(true, Ordering::SeqCst);
    if let Some(child) = slot.as_mut() {
        let _ = child.kill();
    }
    Ok(())
}
pub fn stop_tor(core: &Core, app: &tauri::AppHandle) -> Result<Value> {
    cancel_tor(core)?;
    let mut tor = core.tor.lock().map_err(|_| "tor-lock")?;
    tor["state"] = json!("stopped");
    tor["progress"] = json!(0);
    let value = tor.clone();
    let _ = app.emit("aegis:event", json!({"type":"tor","data":value}));
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> String {
        format!("[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = [::1]:51820\n",STANDARD.encode([1;32]),STANDARD.encode([2;32]))
    }
    #[test]
    fn scripts_and_duplicate_sections_are_rejected() {
        assert!(profile(&good()).is_ok());
        for addition in [
            "PostUp = evil\n",
            "PreDown = evil\n",
            "Endpoint = bad;evil:1\n",
            "[Interface]\nPrivateKey = x\n",
        ] {
            assert!(profile(&(good() + addition)).is_err());
        }
    }
    #[test]
    fn routing_metadata_is_retained() {
        let (_, meta) = profile(&good()).unwrap();
        assert_eq!(meta["fullTunnel"], true);
        assert_eq!(meta["ipv6"], true);
    }
    #[test]
    fn stop_cancels_reserved_start_before_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(dir.path().into(), dir.path().into()).unwrap();
        reserve_tor(&core).unwrap();
        cancel_tor(&core).unwrap();
        assert!(core.tor_cancel.load(Ordering::SeqCst));
        assert!(reserve_tor(&core).is_err());
        assert!(core.tor_cancel.load(Ordering::SeqCst));
        assert!(core.tor_child.lock().unwrap().is_none());
    }
    #[test]
    fn closing_prevents_tor_reservation() {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::new(dir.path().into(), dir.path().into()).unwrap();
        core.closing.store(true, Ordering::SeqCst);
        assert!(reserve_tor(&core).is_err());
        assert!(!core.tor_busy.load(Ordering::SeqCst));
    }
}
