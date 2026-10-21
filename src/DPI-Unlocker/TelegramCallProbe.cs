using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
namespace DPIUnlocker;
internal static class TelegramCallProbe
{
    public static int Run(string[] args)
    {
        string report=Path.Combine(AppContext.BaseDirectory,"telegram-call-probe.json");
        try
        {
            // Ownership is resolved dynamically: Telegram changes its local ports on rejoin.
            string filter="!loopback and udp";
            IntPtr handle=Divert.WinDivertOpen(filter,0,300,5); // SNIFF | RECV_ONLY: never delays or modifies packets.
            if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error());
            var rows=new Dictionary<string,(int Out,int In,int StunOut,int StunIn)>();
            var owned=new HashSet<(int Port,bool V6)>();
            using var ct=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var reg=ct.Token.Register(()=>Divert.WinDivertShutdown(handle,1));
            try
            {
                byte[] packet=new byte[65535],address=new byte[80];
                while(Divert.WinDivertRecv(handle,packet,(uint)packet.Length,out uint size,address))
                {
                    bool v6=packet[0]>>4==6,outbound=(address[10]&2)!=0;
                    int ip=v6?40:(packet[0]&15)*4;
                    if(size<ip+8||(v6?packet[6]:packet[9])!=17)continue;
                    int localPort=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ip+(outbound?0:2)));
                    if(!owned.Contains((localPort,v6)))
                    {
                        if(!UdpOwner.IsProcess(localPort,v6,"Telegram"))continue;
                        owned.Add((localPort,v6));
                    }
                    int remotePort=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(ip+(outbound?2:0)));
                    string remote=new IPAddress(packet.AsSpan(v6?(outbound?24:8):(outbound?16:12),v6?16:4)).ToString()+":"+remotePort;
                    bool stun=size>=ip+28&&BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(ip+12))==0x2112a442;
                    rows.TryGetValue(remote,out var row);
                    rows[remote]=(row.Out+(outbound?1:0),row.In+(outbound?0:1),row.StunOut+(stun&&outbound?1:0),row.StunIn+(stun&&!outbound?1:0));
                }
            }
            finally{Divert.WinDivertClose(handle);}
            File.WriteAllText(report,JsonSerializer.Serialize(rows.Select(r=>new{Endpoint=r.Key,Sent=r.Value.Out,Received=r.Value.In,StunSent=r.Value.StunOut,StunReceived=r.Value.StunIn}),new JsonSerializerOptions{WriteIndented=true}));
            return 0;
        }
        catch(Exception ex){File.WriteAllText(report,ex.ToString());return 1;}
    }
}
