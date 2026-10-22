using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal sealed class QuicEngine : IDisposable
{
    private IntPtr handle;
    private readonly bool experimental;
    private readonly AiRoutes? ai;
    public QuicEngine(bool experimental=true,AiRoutes? ai=null){this.experimental=experimental;this.ai=ai;}
    public event Action<string>? Log;
    public void Run(CancellationToken ct)
    {
        handle=Divert.WinDivertOpen("outbound and !loopback and !impostor and udp.DstPort == 443 and udp.PayloadLength > 0",0,0,0);
        if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error(),"QUIC WinDivertOpen");
        using var reg=ct.Register(()=>Divert.WinDivertShutdown(handle,1));
        var seen=new Dictionary<string,DateTime>();byte[] packet=new byte[65535],addr=new byte[80];
        Log?.Invoke("QUIC: YouTube использует стабильный TCP; экспериментальный обход остальных QUIC="+experimental);
        try
        {
            while(Divert.WinDivertRecv(handle,packet,(uint)packet.Length,out uint count,addr))
            {
                if(seen.Count>4096)foreach(var keyToRemove in seen.Where(x=>DateTime.UtcNow-x.Value>TimeSpan.FromSeconds(30)).Select(x=>x.Key).ToArray())seen.Remove(keyToRemove);
                try
                {
                    int udp=(packet[0]>>4)==4?(packet[0]&15)*4:40;
                    bool v6=packet[0]>>4==6;
                    bool valid=v6?packet[6]==17:(packet[9]==17 && (BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6))&0x3fff)==0);
                    int payload=udp+8;
                    string? destination=valid?new System.Net.IPAddress(packet.AsSpan(v6?24:16,v6?16:4)).ToString():null;
                    bool aiEndpoint=destination is not null&&ai?.IsEndpoint(destination)==true;
                    if(valid&&count>payload&&(aiEndpoint||VideoEndpoints.IsVideoEndpoint(destination!)))
                    {
                        string flow="tcp-fallback:"+Convert.ToHexString(packet.AsSpan(v6?8:12,v6?32:8))+Convert.ToHexString(packet.AsSpan(udp,4));
                        if(!seen.TryGetValue(flow,out var rejected)||DateTime.UtcNow-rejected>TimeSpan.FromSeconds(1))
                        {
                            seen[flow]=DateTime.UtcNow;
                            byte[] inbound=(byte[])addr.Clone();inbound[10]&=0xfd;
                            Send(PortUnreachable(packet.AsSpan(0,(int)count),udp,v6),inbound);
                            Log?.Invoke((aiEndpoint?"AI_QUIC_FALLBACK":"VIDEO_QUIC_FALLBACK")+" endpoint="+destination);
                        }
                        continue;
                    }
                    if(experimental && valid && count>=payload+1200 && (packet[payload]&0xf0)==0xc0 && BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(payload+1))==1)
                    {
                        string key=Convert.ToHexString(packet.AsSpan(v6?8:12,v6?32:8))+Convert.ToHexString(packet.AsSpan(udp,4));
                        if(!seen.TryGetValue(key,out var when)||DateTime.UtcNow-when>TimeSpan.FromSeconds(15))
                        {
                            seen[key]=DateTime.UtcNow;
                            byte[] fake=new byte[payload+1200];packet.AsSpan(0,payload).CopyTo(fake);QuicInitial.Create().CopyTo(fake,payload);
                            BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(udp+4),1208);
                            BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(v6?4:2),(ushort)(fake.Length-(v6?40:0)));
                            for(int i=0;i<3;i++)Send(fake,addr);
                        }
                    }
                }
                catch(Exception ex){Log?.Invoke("QUIC_ERROR "+ex.Message);}
                Send(packet.AsSpan(0,(int)count).ToArray(),addr);
            }
            if(!ct.IsCancellationRequested)throw new Win32Exception(Marshal.GetLastWin32Error(),"QUIC recv stopped");
        }
        finally{Dispose();}
    }
    internal static byte[] PortUnreachable(ReadOnlySpan<byte> original,int udp,bool v6)
    {
        int ip=v6?40:20,quoted=Math.Min(original.Length,v6?1232:udp+8);
        byte[] result=new byte[ip+8+quoted];result[0]=v6?(byte)0x60:(byte)0x45;
        if(v6)
        {
            result[6]=58;result[7]=64;
            original.Slice(24,16).CopyTo(result.AsSpan(8));original.Slice(8,16).CopyTo(result.AsSpan(24));
        }
        else
        {
            result[8]=64;result[9]=1;
            original.Slice(16,4).CopyTo(result.AsSpan(12));original.Slice(12,4).CopyTo(result.AsSpan(16));
        }
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(v6?4:2),(ushort)(result.Length-(v6?40:0)));
        result[ip]=v6?(byte)1:(byte)3;result[ip+1]=v6?(byte)4:(byte)3;
        original[..quoted].CopyTo(result.AsSpan(ip+8));return result;
    }
    private void Send(byte[] packet,byte[] addr)
    {
        Divert.WinDivertHelperCalcChecksums(packet,(uint)packet.Length,addr,0);
        if(!Divert.WinDivertSend(handle,packet,(uint)packet.Length,out _,addr))throw new Win32Exception(Marshal.GetLastWin32Error(),"QUIC send");
    }
    public void Dispose(){if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1)){Divert.WinDivertClose(handle);handle=IntPtr.Zero;}}
}

