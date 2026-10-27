use crate::store::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
pub struct Output {
    pub code: i32,
    pub text: String,
}
pub fn command(file: &Path, args: &[String]) -> Command {
    let mut command = Command::new(file);
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}
pub fn capture(
    file: &Path,
    args: &[String],
    seconds: u64,
    input: Option<Vec<u8>>,
    env: &[(String, String)],
) -> Result<Output> {
    let mut cmd = command(file, args);
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("missing-process-output")?;
    let stderr = child.stderr.take().ok_or("missing-process-output")?;
    let read = |mut pipe: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut buffer = [0; 8192];
            while let Ok(n) = pipe.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let remaining = 8 * 1024 * 1024usize - bytes.len();
                bytes.extend_from_slice(&buffer[..n.min(remaining)]);
            }
            String::from_utf8_lossy(&bytes).to_string()
        })
    };
    let out = read(Box::new(stdout));
    let err = read(Box::new(stderr));
    if let Some(bytes) = input {
        if let Some(mut stdin) = child.stdin.take() {
            thread::spawn(move || {
                let _ = stdin.write_all(&bytes);
            });
        }
    }
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() < Duration::from_secs(seconds) => {
                thread::sleep(Duration::from_millis(40))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("operation-timeout".into());
            }
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    Ok(Output {
        code: status.code().unwrap_or(-1),
        text: if status.success() {
            stdout.trim().into()
        } else {
            format!("{}\n{}", stderr, stdout).trim().into()
        },
    })
}
pub fn run(file: &Path, args: &[String]) -> Result<String> {
    let out = capture(file, args, 30, None, &[])?;
    if out.code != 0 {
        return Err(out.text.chars().take(1400).collect());
    }
    Ok(out.text)
}
pub fn powershell() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe")
}
pub fn encoded(script: &str) -> String {
    STANDARD.encode(
        script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    )
}
pub fn ps(script: &str) -> Result<String> {
    let script=format!("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); {}",script);
    run(
        &powershell(),
        &[
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-InputFormat".into(),
            "Text".into(),
            "-OutputFormat".into(),
            "Text".into(),
            "-EncodedCommand".into(),
            encoded(&script),
        ],
    )
}
pub fn ps_json(script: &str) -> Result<serde_json::Value> {
    let text = ps(script)?;
    if text.is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(text.trim_start_matches('\u{feff}')).map_err(|e| e.to_string())
}
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
pub fn tool(name: &str, extra: &[PathBuf]) -> Option<PathBuf> {
    let mut candidates = extra.to_vec();
    #[cfg(not(windows))]
    for dir in [
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
    ] {
        candidates.push(Path::new(dir).join(name));
    }
    #[cfg(windows)]
    {
        candidates.push(
            PathBuf::from(
                std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()),
            )
            .join(name)
            .join(format!("{name}.exe")),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}
pub fn elevate(file: &Path, args: &[String]) -> Result<String> {
    #[cfg(windows)]
    {
        if file != powershell() {
            return Err("invalid-elevation-target".into());
        }
        let parameters = args.join(" ");
        let script=format!("$p=Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -WindowStyle Hidden -Wait -PassThru; if($p.ExitCode -ne 0){{throw 'Administrative operation failed'}}",quote(&file.to_string_lossy()),quote(&parameters));
        let out = capture(
            &powershell(),
            &[
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-EncodedCommand".into(),
                encoded(&script),
            ],
            180,
            None,
            &[],
        )?;
        if out.code != 0 {
            return Err(out.text);
        }
        Ok(out.text)
    }
    #[cfg(target_os = "macos")]
    {
        let text = std::iter::once(file.to_string_lossy().into_owned())
            .chain(args.iter().cloned())
            .map(|s| shell_quote(&s))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "do shell script {} with administrator privileges",
            serde_json::to_string(&text).map_err(|e| e.to_string())?
        );
        let out = capture(
            Path::new("/usr/bin/osascript"),
            &["-e".into(), script],
            180,
            None,
            &[],
        )?;
        if out.code != 0 {
            return Err(out.text);
        }
        Ok(out.text)
    }
    #[cfg(target_os = "linux")]
    {
        let pkexec = tool("pkexec", &[]).ok_or("policykit-required")?;
        let mut all = vec![file.to_string_lossy().into_owned()];
        all.extend(args.iter().cloned());
        let out = capture(&pkexec, &all, 180, None, &[])?;
        if out.code != 0 {
            return Err(out.text);
        }
        Ok(out.text)
    }
}
pub fn elevated_ps(script: &str) -> Result<String> {
    let script = format!(
        "$ErrorActionPreference='Stop'; try{{ {}; exit 0 }}catch{{exit 1}}",
        script
    );
    elevate(
        &powershell(),
        &[
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-EncodedCommand".into(),
            encoded(&script),
        ],
    )
}
pub fn runtime_env(resources: &Path, engine: &str) -> Vec<(String, String)> {
    let root = resources.join(engine);
    let mut paths = vec![
        root.clone(),
        root.join("tor"),
        root.join("lib"),
        root.join("lib64"),
    ];
    let key = if cfg!(target_os = "macos") {
        "DYLD_LIBRARY_PATH"
    } else if cfg!(windows) {
        "PATH"
    } else {
        "LD_LIBRARY_PATH"
    };
    if let Some(inherited) = std::env::var_os(key) {
        paths.extend(std::env::split_paths(&inherited));
    }
    let mut result = vec![(
        key.into(),
        std::env::join_paths(paths)
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
    )];
    if engine == "clamav" {
        let certs = root.join("certs");
        if certs.join("clamav.crt").is_file() {
            result.push(("CVD_CERTS_DIR".into(), certs.to_string_lossy().into_owned()));
        }
    }
    result
}
pub fn engine(resources: &Path, group: &str, name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.into()
    };
    tool(
        name,
        &[
            resources.join(group).join(&exe),
            resources.join(group).join("bin").join(&exe),
            resources.join(group).join("usr/local/bin").join(&exe),
            resources.join(group).join(group).join(&exe),
        ],
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_preserves_metacharacters() {
        assert_eq!(quote("a'$(b)"), "'a''$(b)'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert!(!encoded("$x='☘'").contains('$'));
    }
}
