'use strict';
const { execFile, spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const SYSTEM = process.env.SystemRoot || 'C:\\Windows';
const POWERSHELL = path.join(SYSTEM, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
const psQuote = value => "'" + String(value).replace(/'/g, "''") + "'";
function run(file, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    const {input,...executionOptions}=options;
    const child=execFile(file, args, { windowsHide: true, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 25000, ...executionOptions }, (error, stdout, stderr) => {
      if (error) {
        error.output = stdout;
        error.message = (stderr || stdout || error.message).trim().slice(0, 1400);
        reject(error);
      } else resolve(stdout.trim());
    });
    child.stdin?.on('error',()=>{});
    if(input!==undefined)child.stdin?.end(input);else child.stdin?.end();
  });
}
function ps(script, options = {}) {
  const prelude = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new(); ";
  return run(POWERSHELL, ['-NoLogo', '-NoProfile', '-NonInteractive','-InputFormat','Text','-OutputFormat','Text', '-EncodedCommand', Buffer.from(prelude + script, 'utf16le').toString('base64')], options);
}
async function psJSON(script, options) {
  const result = await ps(script, options);
  if (!result) return null;
  return JSON.parse(result.replace(/^\uFEFF/, ''));
}
async function exists(file) { try { await fs.promises.access(file, fs.constants.F_OK); return true; } catch { return false; } }
async function findTool(name, extra = []) {
  const candidates = [...extra];
  if (process.platform === 'win32') {
    candidates.push(path.join(process.env.ProgramFiles || 'C:\\Program Files', name, name + '.exe'));
  } else {
    candidates.push(...['/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin', '/opt/homebrew/bin', '/opt/homebrew/sbin'].map(dir => path.join(dir, name)));
  }
  for (const candidate of candidates) if (await exists(candidate)) return candidate;
  return null;
}
async function elevate(file, args) {
  if (process.platform === 'win32') {
    if (file !== POWERSHELL) throw new Error('Operação administrativa inválida.');
    const result = await ps("$p=Start-Process -FilePath " + psQuote(file) + " -ArgumentList " + psQuote(args.join(' ')) + " -Verb RunAs -WindowStyle Hidden -Wait -PassThru; $p.ExitCode", { timeout: 120000 });
    if (Number(result) !== 0) throw new Error('A operação administrativa não foi concluída. Verifique a autorização e as políticas do sistema.');
  } else if (process.platform === 'darwin') {
    const shellQuote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
    const command = [file, ...args].map(shellQuote).join(' ');
    return await run('/usr/bin/osascript', ['-e', 'do shell script ' + JSON.stringify(command) + ' with administrator privileges'], { timeout: 120000 });
  } else {
    const pkexec = await findTool('pkexec');
    if (!pkexec) throw new Error('Instale o PolicyKit (pkexec) para autorizar esta operação administrativa.');
    return await run(pkexec, [file, ...args], { timeout: 120000 });
  }
}
async function elevatedPS(script) {
  const payload = "$ErrorActionPreference='Stop'; try { " + script + "; exit 0 } catch { exit 1 }";
  return elevate(POWERSHELL, ['-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(payload,'utf16le').toString('base64')]);
}
module.exports = { run, ps, psJSON, psQuote, exists, findTool, elevate, elevatedPS, POWERSHELL, spawn };

