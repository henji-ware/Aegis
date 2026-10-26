'use strict';
const{ps}=require('../electron/runner.cjs'),{protectScript}=require('../electron/dpapi.cjs'),assert=require('node:assert/strict');
const declaration=[
'using System; using System.ComponentModel; using System.Runtime.InteropServices;',
'public static class AegisDpapiCheck {',
' [StructLayout(LayoutKind.Sequential)] public struct Blob {public int Size;public IntPtr Data;}',
' [DllImport("crypt32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CryptUnprotectData(ref Blob input,out IntPtr description,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);',
' [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr data);',
' public static string Check(byte[] data){var input=new Blob{Size=data.Length,Data=Marshal.AllocHGlobal(data.Length)};var output=new Blob();IntPtr desc=IntPtr.Zero;try{Marshal.Copy(data,0,input.Data,data.Length);if(!CryptUnprotectData(ref input,out desc,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,1,out output))throw new Win32Exception(Marshal.GetLastWin32Error());var plain=new byte[output.Size];Marshal.Copy(output.Data,plain,0,plain.Length);return Marshal.PtrToStringUni(desc)+"|"+Convert.ToBase64String(plain);}finally{Marshal.FreeHGlobal(input.Data);if(desc!=IntPtr.Zero)LocalFree(desc);if(output.Data!=IntPtr.Zero)LocalFree(output.Data);}}',
'}'].join('\n');
(async()=>{if(process.platform!=='win32')throw new Error('Execute no Windows.');
const harmless='Aegis native compatibility test. No VPN credentials.';
const blob=await ps(protectScript('ag1234567890'),{input:Buffer.from(harmless).toString('base64')});
const result=await ps('Add-Type -TypeDefinition @"\n'+declaration+'\n"@\n[AegisDpapiCheck]::Check([Convert]::FromBase64String([Console]::In.ReadToEnd()))',{input:blob});
assert.equal(result,'ag1234567890|'+Buffer.from(harmless).toString('base64'));
console.log('Native DPAPI round-trip and WireGuard description: PASS (no service, routes or firewall changes).');
})().catch(error=>{console.error(error.message);process.exitCode=1;});

