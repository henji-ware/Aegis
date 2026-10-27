use crate::{
    antivirus, platform,
    store::{self, Result},
    Core,
};
use serde_json::{json, Value};
fn check(
    id: &str,
    title: &str,
    status: &str,
    evidence: Value,
    recommendation: &str,
    action: Option<&str>,
) -> Value {
    json!({"id":id,"title":title,"status":status,"evidence":if let Some(s)=evidence.as_str(){s.to_string()}else{serde_json::to_string_pretty(&evidence).unwrap_or_default()},"recommendation":recommendation,"action":action})
}
pub fn run(core: &Core) -> Result<Value> {
    let firewall = platform::firewall();
    let network = platform::connections();
    let extras = platform::extra();
    let av = antivirus::status(core);
    let guard = platform::guard();
    let enabled = firewall.as_ref().ok().and_then(|fw| {
        if let Some(profiles) = fw["profiles"].as_array() {
            if profiles.is_empty() {
                None
            } else {
                Some(
                    profiles
                        .iter()
                        .all(|p| p["Enabled"] == true || p["Enabled"] == 1),
                )
            }
        } else {
            fw["enabled"].as_bool()
        }
    });
    let mut checks = vec![check(
        "firewall",
        "Firewall do sistema",
        match enabled {
            Some(true) => "pass",
            Some(false) => "warning",
            None => "unknown",
        },
        firewall.map_err(|e| json!(e)).unwrap_or_else(|e| e),
        "Revise a proteção de entrada e aplique regras reversíveis.",
        Some("firewall"),
    )];
    if cfg!(windows) {
        let g = &guard["guard"];
        let sac = guard["sac"].as_u64().filter(|n| *n <= 2);
        let ci = g["UsermodeCodeIntegrityPolicyEnforcementStatus"]
            .as_u64()
            .filter(|n| *n <= 2);
        let enforced = sac == Some(1) || ci == Some(2);
        let vbs = g["VirtualizationBasedSecurityStatus"]
            .as_u64()
            .filter(|n| *n <= 2);
        let services = g["SecurityServicesRunning"]
            .as_array()
            .filter(|a| a.iter().all(|n| n.as_u64().is_some()));
        checks.extend([
 check("app-control","Controle de aplicativos do Windows",if enforced{"pass"}else if sac.is_some()&&ci.is_some(){"review"}else{"unknown"},guard.clone(),"Confira o controle de aplicativos e os eventos CodeIntegrity na Segurança do Windows.",None),
 check("vbs","Segurança baseada em virtualização",match vbs{Some(2)=>"pass",Some(_)=>"review",None=>"unknown"},json!({"VirtualizationBasedSecurityStatus":vbs}),"Confira a segurança do dispositivo nas configurações do sistema.",None),
 check("memory-integrity","Integridade da memória",match services{Some(a)if a.contains(&json!(2))=>"pass",Some(_)=>"review",None=>"unknown"},json!({"SecurityServicesRunning":services}),"Revise a integridade da memória e a compatibilidade dos drivers.",None)]);
    }
    let av = av.unwrap_or_else(|error| json!({"error":error}));
    let ready =
        av["installed"] == true && av["runnable"] == true && av["signatures"]["ready"] == true;
    checks.push(check("antivirus","Mecanismo de varredura",if ready{"pass"}else{"warning"},json!({"installed":av["installed"],"runnable":av["runnable"],"version":av["version"],"signaturesReady":av["signatures"]["ready"]}),"Prepare o mecanismo e atualize as assinaturas na área Antivírus.",Some("antivirus")));
    let updated = av["signatures"]["updatedAt"]
        .as_str()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok());
    let age = updated.map(|v| chrono::Utc::now().signed_duration_since(v).num_seconds());
    checks.push(check(
        "signatures",
        "Atualização local das assinaturas",
        match age {
            Some(n) if (0..=172800).contains(&n) => "pass",
            Some(n) if n > 172800 => "warning",
            _ => "unknown",
        },
        av["signatures"].clone(),
        "Atualize as assinaturas com FreshClam; o horário local não confirma a versão da base.",
        Some("antivirus"),
    ));
    let listeners = network.as_ref().map(|rows| {
        rows.iter()
            .filter(|r| {
                r["state"] == "Listen"
                    && !platform::loopback(r["localAddress"].as_str().unwrap_or(""))
            })
            .count()
    });
    checks.push(check(
        "listeners",
        "Serviços em escuta na rede",
        match listeners {
            Ok(0) => "pass",
            Ok(_) => "review",
            Err(_) => "unknown",
        },
        json!({"nonLoopbackTcpListeners":listeners.ok(),"error":network.as_ref().err()}),
        "Confirme se os serviços em escuta são necessários e revise o firewall.",
        Some("network"),
    ));
    if cfg!(windows) {
        let admins = extras["admins"].as_array();
        checks.push(check(
            "admins",
            "Contas administrativas",
            match admins {
                Some(a) if a.len() <= 2 => "pass",
                Some(_) => "review",
                None => "unknown",
            },
            extras["admins"].clone(),
            "Mantenha privilégios administrativos apenas nas contas que precisam deles.",
            None,
        ));
        let volumes = extras["encryption"].as_array().filter(|a| !a.is_empty());
        checks.push(check(
            "encryption",
            "Criptografia dos volumes",
            match volumes {
                Some(a)
                    if a.iter()
                        .all(|v| v["ProtectionStatus"] == 1 || v["ProtectionStatus"] == "On") =>
                {
                    "pass"
                }
                Some(_) => "review",
                None => "unknown",
            },
            extras["encryption"].clone(),
            "Confira a criptografia do disco e guarde a chave de recuperação em um local seguro.",
            None,
        ));
        checks.push(check(
            "updates",
            "Último hotfix registrado",
            if extras["updates"].is_null() {
                "unknown"
            } else {
                "review"
            },
            extras["updates"].clone(),
            "Confira o Windows Update; a data de um hotfix não confirma todas as atualizações.",
            None,
        ));
    } else {
        let text = extras["encryptionText"].as_str().unwrap_or("");
        checks.push(check(
            "encryption",
            "Criptografia do disco",
            if text.contains("FileVault is On") {
                "pass"
            } else if text.is_empty() {
                "unknown"
            } else {
                "review"
            },
            extras,
            "Confira a criptografia nas configurações do sistema.",
            None,
        ));
    }
    let mut counts = json!({"pass":0,"warning":0,"review":0,"unknown":0});
    for c in &checks {
        let key = c["status"].as_str().unwrap();
        counts[key] = json!(counts[key].as_u64().unwrap() + 1);
    }
    Ok(
        json!({"id":store::id(),"at":store::now(),"system":platform::system(),"checks":checks,"counts":counts}),
    )
}
#[cfg(test)]
mod tests {
    #[test]
    fn strict_guard_enums() {
        let known = |v: serde_json::Value| v.as_u64().filter(|n| *n <= 2);
        assert_eq!(known(serde_json::json!("2")), None);
        assert_eq!(known(serde_json::json!(99)), None);
        assert_eq!(known(serde_json::json!(2)), Some(2));
    }
}
