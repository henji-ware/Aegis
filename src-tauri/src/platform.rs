use crate::{runner::*, store::Result};
use regex::Regex;
use serde_json::{json, Value};
use std::{net::IpAddr, path::Path};
pub const CONNECTION_LIMIT: usize = 350;
fn list(value: Value) -> Vec<Value> {
    match value {
        Value::Array(a) => a,
        Value::Null => vec![],
        other => vec![other],
    }
}
pub fn system() -> Value {
    let mut info = sysinfo::System::new();
    info.refresh_memory();
    json!({"platform":platform(),"release":sysinfo::System::kernel_version().unwrap_or_default(),"architecture":std::env::consts::ARCH,"hostname":sysinfo::System::host_name().unwrap_or_default(),"os":if cfg!(windows){"Windows"}else if cfg!(target_os="macos"){"macOS"}else{"Linux"},"memory":info.total_memory(),"cpus":std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1),"interfaces":get_if_addrs::get_if_addrs().unwrap_or_default().into_iter().filter(|i|!i.is_loopback()).map(|i|json!({"name":i.name,"address":i.addr.ip().to_string(),"family":if i.addr.ip().is_ipv4(){"IPv4"}else{"IPv6"}})).collect::<Vec<_>>()})
}
pub fn platform() -> &'static str {
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}
pub fn firewall() -> Result<Value> {
    if cfg!(windows) {
        return Ok(
            json!({"backend":"Windows Firewall","supported":true,"profiles":list(ps_json("Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")?)}),
        );
    }
    if cfg!(target_os = "macos") {
        let file = Path::new("/usr/libexec/ApplicationFirewall/socketfilterfw");
        let global = run(file, &["--getglobalstate".into()])?;
        let stealth = run(file, &["--getstealthmode".into()])?;
        return Ok(
            json!({"backend":"macOS Application Firewall","supported":true,"enabled":global.contains("enabled")||global.contains("State = 1"),"stealth":stealth.contains("enabled")||stealth.contains("mode is on"),"evidence":format!("{global}\n{stealth}")}),
        );
    }
    if let Some(ufw) = tool("ufw", &[]) {
        match run(&ufw, &["status".into(), "verbose".into()]) {
            Ok(text) => Ok(
                json!({"backend":"UFW","supported":true,"enabled":text.contains("Status: active"),"evidence":text}),
            ),
            Err(error) => Ok(
                json!({"backend":"UFW","supported":true,"runtimeVerified":false,"evidence":error}),
            ),
        }
    } else {
        Ok(json!({"backend":"UFW","supported":false,"evidence":"ufw-required"}))
    }
}
pub fn endpoint(text: &str) -> (String, u16) {
    let text = text.trim();
    if let Some((host, port)) = text.rsplit_once(':') {
        return (
            host.trim_matches(['[', ']']).into(),
            port.parse().unwrap_or(0),
        );
    }
    (text.into(), 0)
}
pub fn parse_ss(text: &str) -> Vec<Value> {
    let mut rows = vec![];
    let pid_re = Regex::new(r#"\("([^"]+)",pid=(\d+)"#).unwrap();
    for line in text.lines() {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() < 5 {
            continue;
        }
        let state = match cols[0] {
            "ESTAB" => "Established",
            "LISTEN" => "Listen",
            _ => continue,
        };
        let (la, lp) = endpoint(cols[3]);
        let (ra, rp) = endpoint(cols[4]);
        let m = pid_re.captures(line);
        rows.push(json!({"id":format!("ss-{}",rows.len()),"protocol":"TCP","localAddress":la,"localPort":lp,"remoteAddress":ra,"remotePort":rp,"state":state,"pid":m.as_ref().and_then(|c|c[2].parse::<u32>().ok()).unwrap_or(0),"process":m.as_ref().map(|c|c[1].to_string()).unwrap_or_default()}));
        if rows.len() == CONNECTION_LIMIT {
            break;
        }
    }
    rows
}
pub fn parse_lsof(text: &str) -> Vec<Value> {
    let mut rows = vec![];
    let (mut pid, mut process, mut address) = (0u32, String::new(), String::new());
    for line in text.lines() {
        if let Some(v) = line.strip_prefix('p') {
            pid = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix('c') {
            process = v.into();
        } else if let Some(v) = line.strip_prefix('n') {
            address = v.into();
        } else if let Some(v) = line.strip_prefix("TST=") {
            let state = match v {
                "LISTEN" => "Listen",
                "ESTABLISHED" => "Established",
                _ => continue,
            };
            let (local, remote) = address.split_once("->").unwrap_or((&address, "*:0"));
            let (la, lp) = endpoint(local);
            let (ra, rp) = endpoint(remote);
            rows.push(json!({"id":format!("lsof-{}-{}",pid,rows.len()),"protocol":"TCP","localAddress":la,"localPort":lp,"remoteAddress":ra,"remotePort":rp,"state":state,"pid":pid,"process":process}));
            if rows.len() == CONNECTION_LIMIT {
                break;
            }
        }
    }
    rows
}
pub fn connections() -> Result<Vec<Value>> {
    if cfg!(windows) {
        let script = "$procs=@{}; Get-Process | ForEach-Object {$procs[$_.Id]=$_.ProcessName}; @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.State -in @('Established','Listen')} | Select-Object -First __LIMIT__ | ForEach-Object {[pscustomobject]@{protocol='TCP';localAddress=$_.LocalAddress;localPort=$_.LocalPort;remoteAddress=$_.RemoteAddress;remotePort=$_.RemotePort;state=[string]$_.State;pid=$_.OwningProcess;process=$procs[[int]$_.OwningProcess]}}) | ConvertTo-Json -Compress".replace("__LIMIT__", &CONNECTION_LIMIT.to_string());
        let values = list(ps_json(&script)?);
        return Ok(values
            .into_iter()
            .enumerate()
            .map(|(i, mut v)| {
                v["id"] = json!(format!(
                    "{}-{}-{}-{}-{}",
                    v["pid"], v["localPort"], v["remoteAddress"], v["remotePort"], i
                ));
                v
            })
            .collect());
    }
    if cfg!(target_os = "macos") {
        let out = capture(
            Path::new("/usr/sbin/lsof"),
            &["-nP".into(), "-iTCP".into(), "-FpcnT".into()],
            30,
            None,
            &[],
        )?;
        if out.code == 1 && out.text.is_empty() {
            return Ok(vec![]);
        }
        if out.code != 0 {
            return Err(out.text);
        }
        return Ok(parse_lsof(&out.text));
    }
    let ss = tool("ss", &[]).ok_or("iproute2-required")?;
    Ok(parse_ss(&run(
        &ss,
        &[
            "-H".into(),
            "-t".into(),
            "-a".into(),
            "-n".into(),
            "-p".into(),
        ],
    )?))
}
pub fn loopback(address: &str) -> bool {
    address
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}
pub fn guard() -> Value {
    if !cfg!(windows) {
        return Value::Null;
    }
    ps_json(r#"$out=[ordered]@{};try{$out.sac=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState}catch{};try{$out.guard=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning,UsermodeCodeIntegrityPolicyEnforcementStatus}catch{};$out | ConvertTo-Json -Depth 4 -Compress"#).unwrap_or(Value::Null)
}
pub fn extra() -> Value {
    if cfg!(windows) {
        return ps_json(r#"$out=[ordered]@{};try{$out.admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object Name,ObjectClass)}catch{$out.adminError=$_.Exception.Message};try{$out.encryption=@(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,ProtectionStatus,VolumeStatus)}catch{$out.encryptionError=$_.Exception.Message};try{$out.updates=(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ForEach-Object {[pscustomobject]@{id=$_.HotFixID;date=$_.InstalledOn.ToString('o')}})}catch{$out.updatesError=$_.Exception.Message};$out | ConvertTo-Json -Depth 5 -Compress"#).unwrap_or(Value::Null);
    }
    if cfg!(target_os = "macos") {
        return json!({"encryptionText":run(Path::new("/usr/bin/fdesetup"),&["status".into()]).unwrap_or_default()});
    }
    Value::Null
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_and_unattributed_are_retained() {
        let rows=parse_ss("LISTEN 0 128 [::]:443 [::]:*\nESTAB 0 0 127.0.0.1:12 8.8.8.8:443 users:((\"browser\",pid=53,fd=7))\nTIME-WAIT 0 0 1:2 3:4");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["localAddress"], "::");
        assert_eq!(rows[0]["pid"], 0);
        assert_eq!(rows[1]["process"], "browser");
    }
    #[test]
    fn lsof_maps_per_socket_state() {
        let rows = parse_lsof(
            "p12\ncBrowser\nn[::1]:82\nTST=LISTEN\nn10.0.0.1:23->1.1.1.1:443\nTST=ESTABLISHED",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["state"], "Listen");
        assert_eq!(rows[1]["remotePort"], 443);
    }
    #[test]
    fn all_loopback_ranges() {
        assert!(loopback("127.9.2.3"));
        assert!(loopback("::1"));
        assert!(!loopback("0.0.0.0"));
    }
}
