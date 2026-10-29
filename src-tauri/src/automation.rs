use crate::{
    antivirus, platform,
    store::{self, Result},
    Core,
};
use chrono::{DateTime, Datelike, Duration, Local, NaiveDateTime, TimeZone, Utc};
use serde_json::{json, Value};
use std::{collections::HashSet, sync::atomic::Ordering, thread, time::Duration as Wait};
use tauri::Emitter;

pub fn defaults() -> Value {
    json!({"autoDefinitions":false,"background":false,"onboardingDone":false,"schedule":{"enabled":false,"hour":20,"minute":0,"frequency":"daily","type":"quick","catchUp":true}})
}
pub fn valid(key: &str, value: &Value) -> bool {
    match key {
        "autoDefinitions" | "background" | "onboardingDone" => value.is_boolean(),
        "schedule" => value.as_object().is_some_and(|o| {
            o.len() == 6
                && value["enabled"].is_boolean()
                && value["catchUp"].is_boolean()
                && value["hour"].as_u64().is_some_and(|n| n < 24)
                && value["minute"].as_u64().is_some_and(|n| n < 60)
                && matches!(value["frequency"].as_str(), Some("daily" | "weekly"))
                && matches!(value["type"].as_str(), Some("quick" | "full" | "custom"))
        }),
        _ => false,
    }
}
pub fn due(config: &Value, last: &str, now: DateTime<Local>) -> Option<String> {
    if config["enabled"] != true {
        return None;
    }
    let hour = config["hour"].as_u64()? as u32;
    let minute = config["minute"].as_u64()? as u32;
    for offset in 0..8 {
        let day = now.date_naive() - Duration::days(offset);
        if config["frequency"] == "weekly" && day.weekday() != chrono::Weekday::Mon {
            continue;
        }
        let time = Local
            .from_local_datetime(&NaiveDateTime::new(
                day,
                chrono::NaiveTime::from_hms_opt(hour, minute, 0)?,
            ))
            .earliest()?;
        if time > now {
            continue;
        }
        let key = time.to_rfc3339();
        if key.as_str() <= last {
            return None;
        }
        if config["catchUp"] != true && (now - time).num_minutes() > 1 {
            return None;
        }
        return Some(key);
    }
    None
}
pub fn status(core: &Core) -> Result<Value> {
    let s = core.store.lock().map_err(|_| "state-lock")?;
    Ok(
        json!({"settings":s.data["settings"],"state":s.data["automation"],"folder":s.data["scheduleFolder"],"monitor":s.data["networkMonitor"],"events":s.data["networkHistory"]}),
    )
}
fn claim(core: &Core, key: &str, value: Value) -> Result<()> {
    let mut s = core.store.lock().map_err(|_| "state-lock")?;
    s.data["automation"][key] = value;
    s.save()
}
pub fn start(core: Core, app: tauri::AppHandle) {
    thread::spawn(move || {
        let mut previous = HashSet::new();
        let mut initial = true;
        let mut last_monitor = std::time::Instant::now() - Wait::from_secs(20);
        loop {
            if core.closing.load(Ordering::SeqCst) {
                break;
            }
            let (settings, state, folder) = match core.store.lock() {
                Ok(s) => (
                    s.data["settings"].clone(),
                    s.data["automation"].clone(),
                    s.data["scheduleFolder"]
                        .as_str()
                        .map(std::path::PathBuf::from),
                ),
                Err(_) => break,
            };
            if settings["liveNetwork"] == true && last_monitor.elapsed() >= Wait::from_secs(12) {
                match platform::connections() {
                    Ok(rows) => {
                        let current: HashSet<String> = rows.iter().map(connection_key).collect();
                        let mut changes = vec![];
                        if !initial {
                            for row in rows
                                .iter()
                                .filter(|r| !previous.contains(&connection_key(r)))
                                .take(80)
                            {
                                let listener = row["state"] == "Listen"
                                    && !platform::loopback(
                                        row["localAddress"].as_str().unwrap_or(""),
                                    );
                                changes.push(json!({"id":store::id(),"at":store::now(),"kind":if listener{"listener"}else{"connection"},"level":if listener{"review"}else{"info"},"connection":row}));
                            }
                        }
                        if let Ok(mut s) = core.store.lock() {
                            s.data["networkMonitor"] = json!({"checkedAt":store::now(),"error":null,"count":rows.len(),"limited":rows.len()>=350});
                            let list = s.data["networkHistory"].as_array_mut().unwrap();
                            for change in changes.into_iter().rev() {
                                list.insert(0, change);
                            }
                            list.truncate(500);
                            let _ = s.save();
                        }
                        previous = current;
                        initial = false;
                        let _ = app.emit("aegis:event", json!({"type":"connections","data":rows}));
                    }
                    Err(error) => {
                        if let Ok(mut s) = core.store.lock() {
                            s.data["networkMonitor"] =
                                json!({"checkedAt":store::now(),"error":error});
                            let _ = s.save();
                        }
                    }
                }
                last_monitor = std::time::Instant::now();
            } else if settings["liveNetwork"] != true {
                initial = true;
                previous.clear();
            }
            if !core.scan_busy.load(Ordering::SeqCst) && !core.mutation.load(Ordering::SeqCst) {
                let last_update = state["definitionAttempt"]
                    .as_str()
                    .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.with_timezone(&Utc));
                if settings["autoDefinitions"] == true
                    && last_update.is_none_or(|t| Utc::now() - t > Duration::hours(4))
                {
                    if claim(&core, "definitionAttempt", json!(store::now())).is_ok() {
                        match antivirus::start(&core, &app, "update", None) {
                            Ok(job) => {
                                let _ = claim(&core, "lastJob", job["id"].clone());
                            }
                            Err(error) => {
                                let _ = claim(&core, "error", json!(error));
                            }
                        }
                    }
                } else if let Some(key) = due(
                    &settings["schedule"],
                    state["scanAttempt"].as_str().unwrap_or(""),
                    Local::now(),
                ) {
                    if claim(&core, "scanAttempt", json!(key)).is_ok() {
                        let kind = settings["schedule"]["type"].as_str().unwrap_or("quick");
                        match antivirus::start(&core, &app, kind, folder) {
                            Ok(job) => {
                                let _ = claim(&core, "lastJob", job["id"].clone());
                                let _ = claim(&core, "error", Value::Null);
                            }
                            Err(error) => {
                                let _ = claim(&core, "error", json!(error));
                            }
                        }
                    }
                }
            }
            for _ in 0..10 {
                if core.closing.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Wait::from_millis(500));
            }
        }
    });
}
fn connection_key(row: &Value) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        row["pid"],
        row["process"],
        row["localAddress"],
        row["localPort"],
        row["remoteAddress"],
        row["remotePort"],
        row["state"]
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schedule_is_strict() {
        assert!(valid("schedule", &defaults()["schedule"]));
        let mut v = defaults()["schedule"].clone();
        v["hour"] = json!(24);
        assert!(!valid("schedule", &v));
        v["command"] = json!("sh");
        assert!(!valid("schedule", &v));
    }
    #[test]
    fn missed_schedule_runs_once() {
        let mut c = defaults()["schedule"].clone();
        c["enabled"] = json!(true);
        let now = Local
            .with_ymd_and_hms(2026, 10, 28, 21, 30, 0)
            .earliest()
            .unwrap();
        let key = due(&c, "", now).unwrap();
        assert!(due(&c, &key, now).is_none());
        c["catchUp"] = json!(false);
        assert!(due(&c, "", now).is_none());
    }
    #[test]
    fn weekly_is_monday() {
        let mut c = defaults()["schedule"].clone();
        c["enabled"] = json!(true);
        c["frequency"] = json!("weekly");
        let now = Local
            .with_ymd_and_hms(2026, 10, 28, 21, 30, 0)
            .earliest()
            .unwrap();
        let due = DateTime::parse_from_rfc3339(&due(&c, "", now).unwrap()).unwrap();
        assert_eq!(due.weekday(), chrono::Weekday::Mon);
    }
}
