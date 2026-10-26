'use strict';
const declaration=[
'using System; using System.ComponentModel; using System.Runtime.InteropServices;',
'public static class AegisDpapi {',
' [StructLayout(LayoutKind.Sequential)] public struct Blob { public int Size; public IntPtr Data; }',
' [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]',
' static extern bool CryptProtectData(ref Blob input,string name,IntPtr entropy,IntPtr reserved,IntPtr prompt,int flags,out Blob output);',
' [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);',
' public static byte[] Protect(byte[] data,string name) {',
'  var input=new Blob { Size=data.Length, Data=Marshal.AllocHGlobal(data.Length) }; var output=new Blob();',
'  try { Marshal.Copy(data,0,input.Data,data.Length);',
'   if(!CryptProtectData(ref input,name,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero,5,out output))throw new Win32Exception(Marshal.GetLastWin32Error());',
'   var result=new byte[output.Size];Marshal.Copy(output.Data,result,0,output.Size);return result;',
'  } finally { for(int i=0;i<input.Size;i++)Marshal.WriteByte(input.Data,i,0);Marshal.FreeHGlobal(input.Data);if(output.Data!=IntPtr.Zero)LocalFree(output.Data); }',
' }',
'}'
].join('\n');
function protectScript(name){
 if(typeof name!=='string'||!/^ag[a-f0-9]{10}$/.test(name))throw new Error('Nome de túnel inválido.');
 // WireGuard requires the DPAPI description to match the tunnel filename.
 return 'Add-Type -TypeDefinition @"\n'+declaration+'\n"@\n'+
 '$bytes=[Convert]::FromBase64String([Console]::In.ReadToEnd()); try { [Convert]::ToBase64String([AegisDpapi]::Protect($bytes,\''+name+'\')) } finally { [Array]::Clear($bytes,0,$bytes.Length) }';
}
module.exports={protectScript};

