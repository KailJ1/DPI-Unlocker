using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal static class UdpOwner
{
    [DllImport("iphlpapi.dll")]private static extern uint GetExtendedUdpTable(IntPtr table,ref int size,bool sorted,int family,int tableClass,uint reserved);
    public static bool IsDiscord(int port,bool v6)
        =>IsProcess(port,v6,"Discord");
    public static bool IsProcess(int port,bool v6,string processName)
    {
        int size=0,family=v6?23:2;GetExtendedUdpTable(IntPtr.Zero,ref size,false,family,1,0);
        if(size<4||size>16000000)return false;
        IntPtr memory=Marshal.AllocHGlobal(size);
        try
        {
            if(GetExtendedUdpTable(memory,ref size,false,family,1,0)!=0)return false;
            byte[] table=new byte[size];Marshal.Copy(memory,table,0,size);
            int count=BinaryPrimitives.ReadInt32LittleEndian(table),row=v6?28:12,offset=v6?20:4;
            for(int i=0;i<count&&4+(i+1)*row<=size;i++)
            {
                int p=4+i*row;if(BinaryPrimitives.ReadUInt16BigEndian(table.AsSpan(p+offset))!=port)continue;
                int pid=BinaryPrimitives.ReadInt32LittleEndian(table.AsSpan(p+offset+4));
                try{using var process=Process.GetProcessById(pid);if(process.ProcessName.Equals(processName,StringComparison.OrdinalIgnoreCase))return true;}
                catch(ArgumentException){}catch(System.ComponentModel.Win32Exception){}
            }
            return false;
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
}
