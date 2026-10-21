using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal sealed class DiscordVoiceEngine : IDisposable
{
    private IntPtr handle;
    private readonly bool telegram;
    public DiscordVoiceEngine(bool telegram=false){this.telegram=telegram;}
    public event Action<string>? Log;
    internal static bool IsDiscovery(ReadOnlySpan<byte> p)
        =>p.Length==74&&BinaryPrimitives.ReadUInt16BigEndian(p)==1&&BinaryPrimitives.ReadUInt16BigEndian(p[2..])==70&&p.Slice(8,64).IndexOfAnyExcept((byte)0)<0;
    internal static bool IsStun(ReadOnlySpan<byte> p)
        =>p.Length>=20&&(p[0]&0xc0)==0&&BinaryPrimitives.ReadUInt32BigEndian(p[4..])==0x2112a442&&BinaryPrimitives.ReadUInt16BigEndian(p[2..])==p.Length-20&&(p.Length&3)==0;
    internal static byte[] CreateProbe(ReadOnlySpan<byte> packet,int ip,bool v6)
    {
        byte[] fake=new byte[ip+8+1200];packet[..(ip+8)].CopyTo(fake);
        QuicInitial.Create().CopyTo(fake,ip+8);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(ip+4),1208);
        BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(v6?4:2),(ushort)(fake.Length-(v6?40:0)));
        return fake;
    }
    internal static byte[][] Fragment(byte[] packet)
    {
        if(packet.Length<28||packet[0]>>4!=4||packet[9]!=17)return [packet];
        int ip=(packet[0]&15)*4;
        if(ip<20||packet.Length!=ip+82||(BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6))&0x3fff)!=0||!IsDiscovery(packet.AsSpan(ip+8)))return [packet];
        // UDP header plus the discovery header form the first 16-byte fragment.
        // Reassembly yields exactly the original UDP datagram, including checksum.
        byte[] first=packet[..(ip+16)],second=new byte[ip+packet.Length-ip-16];
        packet.AsSpan(0,ip).CopyTo(second);packet.AsSpan(ip+16).CopyTo(second.AsSpan(ip));
        BinaryPrimitives.WriteUInt16BigEndian(first.AsSpan(2),(ushort)first.Length);
        BinaryPrimitives.WriteUInt16BigEndian(second.AsSpan(2),(ushort)second.Length);
        BinaryPrimitives.WriteUInt16BigEndian(first.AsSpan(6),0x2000);
        BinaryPrimitives.WriteUInt16BigEndian(second.AsSpan(6),2);
        return [first,second];
    }
    public void Run(CancellationToken ct)
    {
        handle=Divert.WinDivertOpen(telegram?"!loopback and !impostor and udp and udp.PayloadLength >= 20 and udp.PayloadLength <= 2048":"!loopback and !impostor and udp and udp.PayloadLength == 74",0,telegram?(short)61:(short)60,0);
        if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error(),"Discord voice WinDivertOpen");
        using var reg=ct.Register(()=>Divert.WinDivertShutdown(handle,1));
        Log?.Invoke(telegram?"TELEGRAM_VOICE: Telegram-owned STUN, all IPs/ports; six QUIC decoys before original":"DISCORD_VOICE: Discord-owned discovery, all IPs/ports, IPv4/basic IPv6; six QUIC decoys before original");
        var attempts=new Dictionary<string,(int Count,DateTime Seen)>();
        byte[] buffer=new byte[65535],address=new byte[80];
        try
        {
            while(Divert.WinDivertRecv(handle,buffer,(uint)buffer.Length,out uint count,address))
            {
                // Preserve a valid checksum on the original; recalculate each decoy below.
                Divert.WinDivertHelperCalcChecksums(buffer,count,address,0);
                bool v6=buffer[0]>>4==6;int ip=v6?40:(buffer[0]&15)*4;
                bool valid=v6?count>=ip+28&&buffer[6]==17:ip>=20&&count>=ip+28&&buffer[9]==17&&(BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6))&0x3fff)==0;
                bool outbound=(address[10]&2)!=0;
                byte[][] parts=[buffer[..(int)count]];
                if(valid&&(telegram?IsStun(buffer.AsSpan(ip+8,(int)count-ip-8)):ip+82==count))
                {
                    int source=BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ip)),target=BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ip+2));
                    string remote=new System.Net.IPAddress(buffer.AsSpan(v6?(outbound?24:8):(outbound?16:12),v6?16:4)).ToString();
                    string key=remote+":"+(outbound?target:source)+":"+(outbound?source:target);
                    if(outbound&&(telegram?UdpOwner.IsProcess(source,v6,"Telegram"):IsDiscovery(buffer.AsSpan(ip+8,74))&&UdpOwner.IsDiscord(source,v6)))
                    {
                        int attempt=attempts.TryGetValue(key,out var prior)?prior.Count+1:1;attempts[key]=(attempt,DateTime.UtcNow);
                        int mode=3;
                        if(!telegram||attempt==1||DateTime.UtcNow-prior.Seen>TimeSpan.FromSeconds(3))
                        {
                            byte[] fake=CreateProbe(buffer.AsSpan(0,(int)count),ip,v6);
                            parts=[fake,fake,fake,fake,fake,fake,buffer[..(int)count]];
                            Log?.Invoke($"{(telegram?"TELEGRAM_STUN":"DISCORD_DISCOVERY")} {remote}:{target} local={source} IPv{(v6?6:4)} attempt={attempt} mode={mode}");
                        }
                    }
                    else if(!outbound&&attempts.ContainsKey(key))Log?.Invoke($"{(telegram?"TELEGRAM_STUN_REPLY":"DISCORD_DISCOVERY_REPLY")} {remote}:{source} type={BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ip+8))}");
                    if(attempts.Count>256)foreach(string old in attempts.Where(x=>DateTime.UtcNow-x.Value.Seen>TimeSpan.FromMinutes(2)).Select(x=>x.Key).ToArray())attempts.Remove(old);
                }
                foreach(var part in parts)
                {
                    Divert.WinDivertHelperCalcChecksums(part,(uint)part.Length,address,0);
                    if(!Divert.WinDivertSend(handle,part,(uint)part.Length,out uint sent,address)||sent!=part.Length)throw new Win32Exception(Marshal.GetLastWin32Error(),"Discord UDP send");
                }
            }
            if(!ct.IsCancellationRequested)throw new Win32Exception(Marshal.GetLastWin32Error(),"Discord UDP receive");
        }
        finally{Dispose();}
    }
    public void Dispose(){if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1)){Divert.WinDivertClose(handle);handle=IntPtr.Zero;}}
}
