using System.Runtime.InteropServices;
using System.Buffers.Binary;
using System.Diagnostics;
namespace DPIUnlocker;
internal static class TcpOwner
{
    [DllImport("iphlpapi.dll")]private static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool sorted,int family,int tableClass,uint reserved);
    public static int Find(int port,string remote)
    {
        int size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);if(size<=0||size>16_000_000)return 0;
        IntPtr memory=Marshal.AllocHGlobal(size);
        try
        {
            if(GetExtendedTcpTable(memory,ref size,false,2,5,0)!=0)return 0;
            byte[] table=new byte[size];Marshal.Copy(memory,table,0,size);int count=BinaryPrimitives.ReadInt32LittleEndian(table);
            for(int i=0;i<count&&4+(i+1)*24<=size;i++)
            {
                int p=4+i*24;
                if(BinaryPrimitives.ReadUInt16BigEndian(table.AsSpan(p+8))!=port)continue;
                if(new System.Net.IPAddress(table.AsSpan(p+12,4)).ToString()!=remote)continue;
                return BinaryPrimitives.ReadInt32LittleEndian(table.AsSpan(p+20));
            }
            return 0;
        }
        finally{Marshal.FreeHGlobal(memory);}
    }
    public static bool IsTelegram(int pid)
    {
        try{using var process=Process.GetProcessById(pid);return process.ProcessName.Equals("Telegram",StringComparison.OrdinalIgnoreCase);}catch(ArgumentException){return false;}catch(System.ComponentModel.Win32Exception){return false;}
    }
}

