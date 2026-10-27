use crate::{
    platform,
    runner::*,
    store::{self, Result},
    Core,
};
use serde_json::{json, Value};
use std::{fs, path::Path};
pub fn status(core: &Core) -> Result<Value> {
    let native = platform::firewall().unwrap_or_else(|e| json!({"supported":false,"error":e}));
    let s = core.store.lock().map_err(|_| "state-lock")?;
    Ok(
        json!({"platform":platform::platform(),"native":native,"rules":s.data["rules"],"canRestore":!s.data["firewallBackup"].is_null()}),
    )
}
fn update(core: &Core, field: &str, value: Value) -> Result<()> {
    let mut s = core.store.lock().map_err(|_| "state-lock")?;
    s.data[field] = value;
    s.save()
}
fn ufw() -> Result<std::path::PathBuf> {
    tool("ufw", &[]).ok_or("ufw-required".into())
}
pub fn harden(core: &Core) -> Result<Value> {
    if !core.store.lock().map_err(|_| "state-lock")?.data["firewallBackup"].is_null() {
        return Err("firewall-backup-exists".into());
    }
    let before = if cfg!(windows) {
        let v=ps_json("Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress")?;
        if v.as_array().map(|a| a.len()) != Some(3) {
            return Err("firewall-backup-unavailable".into());
        }
        v
    } else if cfg!(target_os = "macos") {
        platform::firewall()?
    } else {
        let conf = fs::read_to_string("/etc/ufw/ufw.conf").map_err(|e| e.to_string())?;
        let defaults = fs::read_to_string("/etc/default/ufw").map_err(|e| e.to_string())?;
        let re = regex::Regex::new(r#"(?m)^DEFAULT_INPUT_POLICY="(ACCEPT|DROP|REJECT)"$"#).unwrap();
        let policy = re
            .captures(&defaults)
            .ok_or("firewall-backup-unavailable")?[1]
            .to_string();
        json!({"enabled":conf.lines().any(|l|l=="ENABLED=yes"),"policy":policy})
    };
    update(
        core,
        "firewallBackup",
        json!({"platform":platform::platform(),"before":before,"pending":true,"at":store::now()}),
    )?;
    if cfg!(windows) {
        elevated_ps("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block")?;
    } else if cfg!(target_os = "macos") {
        let tool = Path::new("/usr/libexec/ApplicationFirewall/socketfilterfw");
        elevate(tool, &["--setglobalstate".into(), "on".into()])?;
        elevate(tool, &["--setstealthmode".into(), "on".into()])?;
    } else {
        let file = ufw()?;
        elevate(&file, &["default".into(), "deny".into(), "incoming".into()])?;
        elevate(&file, &["--force".into(), "enable".into()])?;
    }
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["firewallBackup"]["pending"] = json!(false);
        s.event(
            "firewall",
            "Reforço do firewall aplicado",
            json!("Configuração anterior salva para restauração."),
            "success",
        )?;
    }
    status(core)
}
pub fn restore(core: &Core) -> Result<Value> {
    let backup = core.store.lock().map_err(|_| "state-lock")?.data["firewallBackup"].clone();
    if backup["platform"] != platform::platform() {
        return Err("firewall-backup-unavailable".into());
    }
    let b = &backup["before"];
    if cfg!(windows) {
        let profiles = b.as_array().ok_or("invalid-firewall-backup")?;
        if profiles.len() != 3 {
            return Err("invalid-firewall-backup".into());
        }
        let mut scripts = vec![];
        for p in profiles {
            let name = p["Name"].as_str().ok_or("invalid-firewall-backup")?;
            if !["Domain", "Private", "Public"].contains(&name) {
                return Err("invalid-firewall-backup".into());
            }
            let enabled = if p["Enabled"] == true || p["Enabled"] == 1 {
                "True"
            } else if p["Enabled"] == false || p["Enabled"] == 0 {
                "False"
            } else {
                "NotConfigured"
            };
            let action = match p["DefaultInboundAction"].as_i64() {
                Some(2) => "Allow",
                Some(4) => "Block",
                _ => match p["DefaultInboundAction"].as_str() {
                    Some("Allow") => "Allow",
                    Some("Block") => "Block",
                    _ => "NotConfigured",
                },
            };
            scripts.push(format!("Set-NetFirewallProfile -Profile {name} -Enabled {enabled} -DefaultInboundAction {action}"));
        }
        elevated_ps(&scripts.join("; "))?;
    } else if cfg!(target_os = "macos") {
        let file = Path::new("/usr/libexec/ApplicationFirewall/socketfilterfw");
        elevate(
            file,
            &[
                "--setglobalstate".into(),
                if b["enabled"] == true { "on" } else { "off" }.into(),
            ],
        )?;
        elevate(
            file,
            &[
                "--setstealthmode".into(),
                if b["stealth"] == true { "on" } else { "off" }.into(),
            ],
        )?;
    } else {
        let file = ufw()?;
        let policy = match b["policy"].as_str() {
            Some("ACCEPT") => "allow",
            Some("DROP") => "deny",
            Some("REJECT") => "reject",
            _ => return Err("invalid-firewall-backup".into()),
        };
        elevate(&file, &["default".into(), policy.into(), "incoming".into()])?;
        elevate(
            &file,
            &[
                "--force".into(),
                if b["enabled"] == true {
                    "enable"
                } else {
                    "disable"
                }
                .into(),
            ],
        )?;
    }
    update(core, "firewallBackup", Value::Null)?;
    core.store.lock().map_err(|_| "state-lock")?.event(
        "firewall",
        "Configuração do firewall restaurada",
        json!("Regras de outros aplicativos foram preservadas."),
        "success",
    )?;
    status(core)
}
pub fn port(value: &Value) -> Result<u16> {
    let number = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .filter(|n| *n > 0 && *n <= 65535)
        .ok_or("invalid-port")?;
    Ok(number as u16)
}
pub fn block(core: &Core, input: &Value) -> Result<Value> {
    if cfg!(target_os = "macos") {
        return Err("macos-application-firewall".into());
    }
    let port = port(input)?;
    if core.store.lock().map_err(|_| "state-lock")?.data["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["port"] == port)
    {
        return Err("rule-exists".into());
    }
    if cfg!(target_os = "linux") {
        let added = elevate(&ufw()?, &["show".into(), "added".into()])?;
        let re = regex::Regex::new(&format!(r"(?:\s|^){port}(?:/tcp|\s|$)")).unwrap();
        if added
            .lines()
            .any(|line| re.is_match(line.split("comment").next().unwrap_or("")))
        {
            return Err("external-rule-exists".into());
        }
    }
    let id = format!("Aegis-{}", store::id());
    let rule = json!({"id":id,"port":port,"pending":true,"at":store::now(),"protocol":"TCP","direction":"inbound"});
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["rules"].as_array_mut().unwrap().insert(0, rule);
        s.save()?;
    }
    if cfg!(windows) {
        elevated_ps(&format!("New-NetFirewallRule -Name {} -DisplayName {} -Group 'Aegis' -Direction Inbound -Protocol TCP -LocalPort {port} -Action Block -Enabled True | Out-Null",quote(&id),quote(&format!("Aegis TCP {port}"))))?;
    } else {
        elevate(
            &ufw()?,
            &[
                "deny".into(),
                "in".into(),
                "proto".into(),
                "tcp".into(),
                "to".into(),
                "any".into(),
                "port".into(),
                port.to_string(),
                "comment".into(),
                id.clone(),
            ],
        )?;
    }
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        if let Some(rule) = s.data["rules"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == id)
        {
            rule["pending"] = json!(false);
        }
        s.event("firewall", "Porta TCP bloqueada", json!(port), "success")?;
    }
    status(core)
}
pub fn remove(core: &Core, id: &str) -> Result<Value> {
    let uuid = id.strip_prefix("Aegis-").ok_or("invalid-rule")?;
    if uuid::Uuid::parse_str(uuid).is_err() {
        return Err("invalid-rule".into());
    }
    let rule = core.store.lock().map_err(|_| "state-lock")?.data["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .cloned()
        .ok_or("invalid-rule")?;
    let port = port(&rule["port"])?;
    if cfg!(windows) {
        elevated_ps(&format!("Get-NetFirewallRule -Name {} -ErrorAction SilentlyContinue | Where-Object {{$_.Group -eq 'Aegis'}} | Remove-NetFirewallRule",quote(id)))?;
    } else if cfg!(target_os = "linux") {
        let file = ufw()?;
        let added = elevate(&file, &["show".into(), "added".into()])?;
        if !added
            .lines()
            .any(|l| l.contains(id) && l.contains(&port.to_string()))
        {
            return Err("rule-ownership-unverified".into());
        }
        elevate(
            &file,
            &[
                "--force".into(),
                "delete".into(),
                "deny".into(),
                "in".into(),
                "proto".into(),
                "tcp".into(),
                "to".into(),
                "any".into(),
                "port".into(),
                port.to_string(),
                "comment".into(),
                id.into(),
            ],
        )?;
    }
    {
        let mut s = core.store.lock().map_err(|_| "state-lock")?;
        s.data["rules"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["id"] != id);
        s.event("firewall", "Regra removida", json!(port), "success")?;
    }
    status(core)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ports_reject_shell_and_fractional_inputs() {
        for input in [
            json!(0),
            json!(65536),
            json!(3.2),
            json!("80; evil"),
            json!("$()"),
        ] {
            assert!(port(&input).is_err());
        }
        assert_eq!(port(&json!("443")).unwrap(), 443);
    }
}
