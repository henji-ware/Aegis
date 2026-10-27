use crate::{
    store::{self, Result},
    Core,
};
use serde_json::{json, Value};
use std::sync::OnceLock;
static CATALOGS: OnceLock<Vec<(&str, Value)>> = OnceLock::new();
pub fn locale(choice: &str) -> String {
    let raw = if choice == "system" {
        std::env::var("LANG").unwrap_or_else(|_| system_locale())
    } else {
        choice.into()
    };
    let raw = raw.to_lowercase();
    if raw.starts_with("pt") {
        return "pt-BR".into();
    }
    if raw.starts_with("zh") {
        return "zh-CN".into();
    }
    let base = raw.split(['-', '_', '.']).next().unwrap_or("en");
    if store::LANGUAGES.contains(&base) {
        base.into()
    } else {
        "en".into()
    }
}
fn system_locale() -> String {
    #[cfg(windows)]
    {
        crate::runner::ps("(Get-UICulture).Name").unwrap_or_else(|_| "en".into())
    }
    #[cfg(not(windows))]
    {
        "en".into()
    }
}
pub fn translate(source: &str, language: &str) -> String {
    let locale = locale(language);
    if locale == "pt-BR" {
        return source.into();
    }
    let catalogs = CATALOGS.get_or_init(|| {
        vec![
            (
                "en",
                serde_json::from_str(include_str!("../../locales/en.json")).unwrap(),
            ),
            (
                "es",
                serde_json::from_str(include_str!("../../locales/es.json")).unwrap(),
            ),
            (
                "fr",
                serde_json::from_str(include_str!("../../locales/fr.json")).unwrap(),
            ),
            (
                "de",
                serde_json::from_str(include_str!("../../locales/de.json")).unwrap(),
            ),
            (
                "ru",
                serde_json::from_str(include_str!("../../locales/ru.json")).unwrap(),
            ),
            (
                "zh-CN",
                serde_json::from_str(include_str!("../../locales/zh-CN.json")).unwrap(),
            ),
            (
                "ja",
                serde_json::from_str(include_str!("../../locales/ja.json")).unwrap(),
            ),
            (
                "ar",
                serde_json::from_str(include_str!("../../locales/ar.json")).unwrap(),
            ),
            (
                "hi",
                serde_json::from_str(include_str!("../../locales/hi.json")).unwrap(),
            ),
        ]
    });
    catalogs
        .iter()
        .find(|(l, _)| *l == locale)
        .and_then(|(_, v)| v[source].as_str())
        .or_else(|| catalogs[0].1[source].as_str())
        .unwrap_or(source)
        .into()
}
pub fn tx(core: &Core, source: &str) -> String {
    let lang = core
        .store
        .lock()
        .ok()
        .and_then(|s| s.data["settings"]["language"].as_str().map(str::to_string))
        .unwrap_or_else(|| "system".into());
    translate(source, &lang)
}
pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn report(core: &Core) -> Result<String> {
    let data = core.store.lock().map_err(|_| "state-lock")?.data.clone();
    let language = data["settings"]["language"].as_str().unwrap_or("system");
    let l = locale(language);
    let t = |s: &str| escape(&translate(s, language));
    let mut html=format!("<!doctype html><html lang=\"{}\" dir=\"{}\"><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Aegis</title><style>body{{font:15px system-ui;max-width:960px;margin:40px auto;padding:24px;color:#183122}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;direction:ltr;text-align:left}}article{{border-bottom:1px solid #ddd;padding:16px 0}}</style><h1>Aegis</h1><p>{}</p><h2>{}</h2>",l,if l=="ar"{"rtl"}else{"ltr"},store::now(),t("Diagnóstico"));
    if let Some(checks) = data["audits"][0]["checks"].as_array() {
        for c in checks {
            let status = match c["status"].as_str() {
                Some("pass") => "Atendido",
                Some("warning") => "Atenção",
                Some("review") => "Revisar",
                _ => "Não verificado",
            };
            html+=&format!("<article><h3>{}</h3><p>{}</p><p>{}</p><details><summary>{}</summary><pre>{}</pre></details></article>",t(c["title"].as_str().unwrap_or("")),t(status),t(c["recommendation"].as_str().unwrap_or("")),t("Detalhes originais"),escape(c["evidence"].as_str().unwrap_or("")));
        }
    }
    html += &format!("<h2>{}</h2>", t("Antivírus"));
    for scan in data["scans"].as_array().unwrap().iter().take(10) {
        html += &format!(
            "<article><p>{}</p><pre>{}</pre></article>",
            escape(scan["startedAt"].as_str().unwrap_or("")),
            escape(&serde_json::to_string_pretty(scan).unwrap_or_default())
        );
    }
    html += &format!("<h2>{}</h2>", t("Atividade"));
    for event in data["history"].as_array().unwrap().iter().take(50) {
        html += &format!(
            "<article><h3>{}</h3><pre>{}</pre></article>",
            t(event["title"].as_str().unwrap_or("Atividade")),
            escape(&event["detail"].to_string())
        );
    }
    html += "</html>";
    Ok(html)
}
pub fn error(detail: &str) -> Value {
    let re = regex::Regex::new(r"[A-Za-z0-9+/]{43}=").unwrap();
    let safe = re
        .replace_all(detail, "[redacted]")
        .chars()
        .take(1400)
        .collect::<String>();
    json!({"code":if detail=="cancelled"{"cancelled"}else if detail.len()<=64&&detail.chars().all(|c|c.is_ascii_lowercase()||c=='-'){detail}else{"operation-failed"},"original":safe})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_escape_original_details() {
        assert_eq!(escape("<script>&\""), "&lt;script&gt;&amp;&quot;");
    }
    #[test]
    fn native_dialogs_use_selected_locale() {
        assert_eq!(translate("Cancelar", "en"), "Cancel");
        assert_eq!(translate("Cancelar", "pt-BR"), "Cancelar");
    }
}
