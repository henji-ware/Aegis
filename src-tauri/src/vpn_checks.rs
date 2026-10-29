use crate::{
    privacy,
    runner::*,
    store::{self, Result},
    Core,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::{IpAddr, ToSocketAddrs},
    path::Path,
};
fn active(core: &Core) -> Result<(Value, Value)> {
    let s = core.store.lock().map_err(|_| "state-lock")?;
    let a = s.data["activeVpn"].clone();
    let meta = s.data["profiles"]
        .as_array()
        .and_then(|p| p.iter().find(|p| p["id"] == a["id"]))
        .map(|p| p["meta"].clone())
        .unwrap_or(Value::Null);
    Ok((a, meta))
}
pub fn diagnose(core: &Core) -> Result<Value> {
    let (active, meta) = active(core)?;
    let observed = if active.is_null() {
        Value::Null
    } else {
        privacy::observe(&active)
    };
    let interface = observed["interfaceName"].as_str().unwrap_or("");
    let mut checks = json!({"tunnel":"unknown","route":"unknown","ipv6":"unknown","dns":"unknown"});
    let mut evidence = json!({"interface":observed});
    if observed["interfaceActive"] == true {
        checks["tunnel"] = json!("pass");
    } else if observed["present"] == false {
        checks["tunnel"] = json!("review");
    }
    if cfg!(windows) {
        let script="$ErrorActionPreference='Stop';$r=@(Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop);$v=@(Find-NetRoute -RemoteIPAddress '2606:4700:4700::1111' -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,InterfaceIndex,DestinationPrefix,NextHop);$d=@(Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses.Count -gt 0} | Select-Object InterfaceAlias,ServerAddresses);[pscustomobject]@{ipv4=$r;ipv6=$v;dns=$d} | ConvertTo-Json -Depth 5 -Compress";
        match ps_json(script) {
            Ok(v) => {
                if observed["interfaceActive"] == true && !interface.is_empty() {
                    let route = v["ipv4"]
                        .as_array()
                        .is_some_and(|rows| rows.iter().any(|r| r["InterfaceAlias"] == interface));
                    checks["route"] = json!(if route { "pass" } else { "review" });
                    let routes = v["ipv6"].as_array();
                    if routes.is_some_and(|r| !r.is_empty()) {
                        checks["ipv6"] = json!(if routes
                            .unwrap()
                            .iter()
                            .any(|r| r["InterfaceAlias"] == interface)
                        {
                            "pass"
                        } else {
                            "review"
                        });
                    }
                    let dns = v["dns"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|r| r["InterfaceAlias"] == interface)
                        .flat_map(|r| r["ServerAddresses"].as_array().into_iter().flatten())
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>();
                    if !dns.is_empty() {
                        let expected = meta["dns"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>();
                        checks["dns"] = json!(if !expected.is_empty()
                            && dns.iter().all(|s| expected.contains(s))
                        {
                            "pass"
                        } else {
                            "review"
                        });
                    }
                }
                evidence["network"] = v;
            }
            Err(e) => evidence["error"] = json!(e),
        }
    } else if cfg!(target_os = "linux") {
        if let Some(ip) = tool("ip", &[]) {
            if let Ok(text) = run(
                &ip,
                &[
                    "-j".into(),
                    "-6".into(),
                    "route".into(),
                    "get".into(),
                    "2606:4700:4700::1111".into(),
                ],
            ) {
                if let Ok(routes) = serde_json::from_str::<Value>(&text) {
                    if !interface.is_empty() && observed["interfaceActive"] == true {
                        checks["ipv6"] = json!(if routes
                            .as_array()
                            .is_some_and(|r| r.iter().any(|r| r["dev"] == interface))
                        {
                            "pass"
                        } else {
                            "review"
                        });
                    }
                    evidence["ipv6Routes"] = routes;
                }
            }
            match run(
                &ip,
                &["-j".into(), "route".into(), "get".into(), "1.1.1.1".into()],
            ) {
                Ok(text) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&text) {
                        if !interface.is_empty() && observed["interfaceActive"] == true {
                            checks["route"] = json!(if v
                                .as_array()
                                .is_some_and(|r| r.iter().any(|r| r["dev"] == interface))
                            {
                                "pass"
                            } else {
                                "review"
                            });
                        }
                        evidence["routes"] = v;
                    }
                }
                Err(e) => evidence["routeError"] = json!(e),
            }
        }
        if let Some(resolvectl) = tool("resolvectl", &[]) {
            match run(&resolvectl, &["dns".into()]) {
                Ok(text) => {
                    evidence["dns"] = json!(text);
                }
                Err(e) => evidence["dnsError"] = json!(e),
            }
        } else {
            evidence["dns"] = fs::read_to_string("/etc/resolv.conf")
                .map(|s| json!(s))
                .unwrap_or(Value::Null);
        }
    } else if cfg!(target_os = "macos") {
        evidence["routes"] = run(
            Path::new("/sbin/route"),
            &["-n".into(), "get".into(), "1.1.1.1".into()],
        )
        .map(|v| json!(v))
        .unwrap_or(Value::Null);
        evidence["dns"] = run(Path::new("/usr/sbin/scutil"), &["--dns".into()])
            .map(|v| json!(v))
            .unwrap_or(Value::Null);
        if let Some(routes) = evidence["routes"].as_str() {
            if !interface.is_empty() {
                checks["route"] = json!(if routes
                    .lines()
                    .any(|l| l.trim() == format!("interface: {interface}"))
                {
                    "pass"
                } else {
                    "review"
                });
            }
        }
    }
    let configured = core.store.lock().map_err(|_| "state-lock")?.data["killSwitch"].clone();
    Ok(
        json!({"checkedAt":store::now(),"checks":checks,"evidence":evidence,"killSwitch":{"supported":cfg!(target_os="linux")&&tool("nft",&[]).is_some(),"configured":!configured.is_null(),"pending":configured["pending"],"nativeWireGuard":cfg!(windows)&&meta["nativeKillSwitch"]==true&&observed["interfaceActive"]==true}}),
    )
}
pub fn public_ip() -> Result<Value> {
    tauri::async_runtime::block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let mut response = client
            .get("https://api64.ipify.org?format=json")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > 4096 {
                return Err("invalid-ip-response".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let data: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let ip: IpAddr = data["ip"]
            .as_str()
            .ok_or("invalid-ip-response")?
            .parse()
            .map_err(|_| "invalid-ip-response")?;
        Ok(json!({"ip":ip.to_string(),"at":store::now(),"provider":"ipify"}))
    })
}
pub fn nft_rules(id: &str, interface: &str, endpoints: &[(IpAddr, u16)]) -> Result<String> {
    if uuid::Uuid::parse_str(id).is_err()
        || !regex::Regex::new("^ag[a-f0-9]{10}$")
            .unwrap()
            .is_match(interface)
        || endpoints.is_empty()
        || endpoints.len() > 16
    {
        return Err("invalid-owned-tunnel".into());
    }
    let table = format!("aegis_{}", uuid::Uuid::parse_str(id).unwrap().simple());
    let mut rules=format!("table inet {table} {{\n comment \"Aegis {id}\"\n chain output {{ type filter hook output priority 0; policy accept;\n oifname \"lo\" accept\n oifname \"{interface}\" accept\n");
    // Preserve only the OS control traffic needed to maintain the underlay.
    // Application traffic still has to use the owned tunnel or its UDP endpoint.
    rules.push_str(" udp sport 68 udp dport 67 accept\n ip6 nexthdr udp udp sport 546 udp dport 547 accept\n meta l4proto ipv6-icmp ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
    for (ip, port) in endpoints {
        if *port == 0 {
            return Err("invalid-vpn-profile".into());
        }
        rules.push_str(&format!(
            " {} daddr {} udp dport {} accept\n",
            if ip.is_ipv4() { "ip" } else { "ip6" },
            ip,
            port
        ));
    }
    rules.push_str(" reject with icmpx type admin-prohibited\n }\n}\n");
    Ok(rules)
}
pub fn protect(core: &Core) -> Result<Value> {
    if !cfg!(target_os = "linux") {
        return Err("kill-switch-unsupported".into());
    }
    let nft = tool("nft", &[]).ok_or("nft-required")?;
    let (active, meta) = active(core)?;
    if active.is_null() || privacy::observe(&active)["interfaceActive"] != true {
        return Err("vpn-not-active".into());
    }
    if !core.store.lock().map_err(|_| "state-lock")?.data["killSwitch"].is_null() {
        return Err("kill-switch-already-active".into());
    }
    if meta["peers"] != 1 {
        return Err("invalid-vpn-profile".into());
    }
    let endpoint = meta["endpoint"].as_str().ok_or("invalid-vpn-profile")?;
    let endpoints = endpoint
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .take(16)
        .map(|s| (s.ip(), s.port()))
        .collect::<Vec<_>>();
    let id = store::id();
    let interface = active["tunnel"].as_str().ok_or("invalid-owned-tunnel")?;
    let rules = nft_rules(&id, interface, &endpoints)?;
    let path = core.dir.join(format!("kill-switch-{id}.nft"));
    store::write_private(&path, rules.as_bytes(), true)?;
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["killSwitch"] = json!({"id":id,"tunnel":interface,"pending":true,"at":store::now()});
        s.save()?;
    }
    let result = elevate(&nft, &["-f".into(), path.to_string_lossy().into_owned()]);
    let _ = fs::remove_file(path);
    result?;
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["killSwitch"]["pending"] = json!(false);
        s.save()?;
    }
    diagnose(core)
}
pub fn unprotect(core: &Core) -> Result<Value> {
    if !cfg!(target_os = "linux") {
        return Err("kill-switch-unsupported".into());
    }
    let state = core.store.lock().map_err(|_| "state-lock")?.data["killSwitch"].clone();
    let id = state["id"].as_str().ok_or("invalid-owned-tunnel")?;
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| "invalid-owned-tunnel")?;
    let nft = tool("nft", &[]).ok_or("nft-required")?;
    let table = format!("aegis_{}", uuid.simple());
    // Read with the same OS authorization as deletion and verify this exact table's owner.
    let output = elevate(&nft, &["-j".into(), "list".into(), "tables".into()])?;
    let data: Value = serde_json::from_str(&output).map_err(|_| "rule-ownership-unverified")?;
    let items = data["nftables"]
        .as_array()
        .ok_or("rule-ownership-unverified")?;
    let present = items
        .iter()
        .any(|v| v["table"]["name"] == table && v["table"]["family"] == "inet");
    if present {
        let output = elevate(
            &nft,
            &[
                "-j".into(),
                "list".into(),
                "table".into(),
                "inet".into(),
                table.clone(),
            ],
        )?;
        let data: Value = serde_json::from_str(&output).map_err(|_| "rule-ownership-unverified")?;
        if !data["nftables"].as_array().is_some_and(|items| {
            items.iter().any(|v| {
                v["table"]["name"] == table && v["table"]["comment"] == format!("Aegis {id}")
            })
        }) {
            return Err("rule-ownership-unverified".into());
        }
        elevate(
            &nft,
            &["delete".into(), "table".into(), "inet".into(), table],
        )?;
    }
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["killSwitch"] = Value::Null;
        s.save()?;
    }
    diagnose(core)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kill_switch_is_scoped_and_endpoint_is_udp_only() {
        let id = store::id();
        let text = nft_rules(
            &id,
            "ag1234567890",
            &[("192.0.2.1".parse().unwrap(), 51820)],
        )
        .unwrap();
        assert!(text.contains("ip daddr 192.0.2.1 udp dport 51820 accept"));
        assert!(text.contains("reject with icmpx"));
        assert!(!text.contains("flush ruleset"));
        assert!(nft_rules(
            &id,
            "eth0\";flush ruleset",
            &[("192.0.2.1".parse().unwrap(), 1)]
        )
        .is_err());
    }
    #[test]
    fn ci_rule_fixture() {
        if cfg!(target_os = "linux") && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
            let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("../.build");
            fs::create_dir_all(&folder).unwrap();
            let rules = nft_rules(
                "00000000-0000-4000-8000-000000000001",
                "ag1234567890",
                &[
                    ("192.0.2.1".parse().unwrap(), 51821),
                    ("fd00:ae::1".parse().unwrap(), 51821),
                ],
            )
            .unwrap();
            fs::write(folder.join("kill-switch-fixture.nft"), rules).unwrap();
        }
    }
}
