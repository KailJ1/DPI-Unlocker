using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;

internal static class TelegramVoiceTrial
{
    internal static byte[][] Fragment(byte[] packet,int cut)
    {
        if(packet.Length<48||packet[0]!=0x45||packet[9]!=17||(BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(6))&0x3fff)!=0||
            !DiscordVoiceEngine.IsStun(packet.AsSpan(28))||cut is not (8 or 16))return [packet];
        byte[] first=packet[..(20+cut)],second=new byte[packet.Length-cut];
        packet.AsSpan(0,20).CopyTo(second);packet.AsSpan(20+cut).CopyTo(second.AsSpan(20));
        BinaryPrimitives.WriteUInt16BigEndian(first.AsSpan(2),(ushort)first.Length);
        BinaryPrimitives.WriteUInt16BigEndian(second.AsSpan(2),(ushort)second.Length);
        BinaryPrimitives.WriteUInt16BigEndian(first.AsSpan(6),0x2000);
        BinaryPrimitives.WriteUInt16BigEndian(second.AsSpan(6),(ushort)(cut/8));
        return [first,second];
    }
    public static int Run(bool decoys=false)
    {
        string report=Path.Combine(AppContext.BaseDirectory,"telegram-voice-trial.txt");
        void Log(string s)=>File.AppendAllText(report,DateTime.Now.ToString("HH:mm:ss ")+s+Environment.NewLine);
        File.WriteAllText(report,"");
        IntPtr handle=Divert.WinDivertOpen("outbound and !loopback and !impostor and ip and udp and udp.PayloadLength >= 20 and udp.PayloadLength <= 2048",0,62,0);
        if(handle==new IntPtr(-1)){Log(new Win32Exception(Marshal.GetLastWin32Error()).Message);return 1;}
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(48));
        using var reg=stop.Token.Register(()=>Divert.WinDivertShutdown(handle,1));
        var start=DateTime.UtcNow;int changed=0,lastMode=-1;ushort identification=(ushort)Random.Shared.Next(65536);
        var lastFake=new Dictionary<string,DateTime>();
        byte[] packet=new byte[65535],address=new byte[80];
        try
        {
            while(Divert.WinDivertRecv(handle,packet,(uint)packet.Length,out uint count,address))
            {
                byte[] original=packet[..(int)count];byte[][] parts=[original];
                if(count>=48&&packet[0]==0x45&&DiscordVoiceEngine.IsStun(packet.AsSpan(28,(int)count-28))&&
                    UdpOwner.IsProcess(BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(20)),false,"Telegram"))
                {
                    int mode=Math.Min(2,(int)(DateTime.UtcNow-start).TotalSeconds/16);
                    if(mode!=lastMode){Log(decoys?$"decoy mode={mode} (zero64, QUIC1200, zero1200)":$"mode={mode} cut={(mode==0?8:16)} reverse={mode==2}");lastMode=mode;}
                    Divert.WinDivertHelperCalcChecksums(original,count,address,0);
                    if(decoys)
                    {
                        string key=Convert.ToHexString(original.AsSpan(12,12));
                        if(!lastFake.TryGetValue(key,out var when)||DateTime.UtcNow-when>TimeSpan.FromSeconds(1))
                        {
                            lastFake[key]=DateTime.UtcNow;
                            byte[] fake=new byte[28+(mode==0?64:1200)];original.AsSpan(0,28).CopyTo(fake);
                            if(mode==1)QuicInitial.Create().CopyTo(fake,28);
                            BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(2),(ushort)fake.Length);
                            BinaryPrimitives.WriteUInt16BigEndian(fake.AsSpan(24),(ushort)(fake.Length-20));
                            Divert.WinDivertHelperCalcChecksums(fake,(uint)fake.Length,address,0);
                            parts=[fake,fake,fake,fake,fake,fake,original];changed++;
                        }
                    }
                    else
                    {
                    parts=Fragment(original,mode==0?8:16);
                    if(parts.Length==2)
                    {
                        identification++;
                        // Preserve UDP checksum over the complete datagram; only IPv4 header checksums change.
                        foreach(var part in parts)
                        {
                            BinaryPrimitives.WriteUInt16BigEndian(part.AsSpan(4),identification);
                            part[10]=part[11]=0;uint sum=0;
                            for(int i=0;i<20;i+=2)sum+=BinaryPrimitives.ReadUInt16BigEndian(part.AsSpan(i));
                            while(sum>65535)sum=(sum&65535)+(sum>>16);
                            BinaryPrimitives.WriteUInt16BigEndian(part.AsSpan(10),(ushort)~sum);
                        }
                        if(mode==2)Array.Reverse(parts);
                        changed++;
                    }
                    }
                }
                foreach(var part in parts)
                    if(!Divert.WinDivertSend(handle,part,(uint)part.Length,out uint sent,address)||sent!=part.Length)
                        throw new Win32Exception(Marshal.GetLastWin32Error(),"Telegram fragment send");
            }
            Log($"completed changed={changed}");return 0;
        }
        catch(Exception ex){Log(ex.ToString());return 1;}
        finally{Divert.WinDivertClose(handle);}
    }
}
