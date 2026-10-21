using System.Buffers.Binary;
using System.Text;
namespace DPIUnlocker;
internal static class SelfTests
{
    private static void Assert(bool value,string name){if(!value)throw new Exception(name);}
    public static int Run()
    {
        try
        {
            Assert(Divert.RetryableOpenError(unchecked((int)0x80320009))&&Divert.RetryableOpenError(unchecked((int)0x8032000a))&&!Divert.RetryableOpenError(1058),"Transient WFP errors distinguished from disabled driver");
            Assert(DriverPrerequisites.DisabledMessage("WinDivert",3) is null,"Demand-start driver accepted");
            Assert(DriverPrerequisites.DisabledMessage("WinDivert",4)!.Contains("1058"),"Disabled driver identified");
            Assert(DriverPrerequisites.DisabledMessage("BFE",4)!.Contains("BFE"),"Disabled BFE distinguished");
            byte[] stunPacket=new byte[68];stunPacket[0]=0x45;stunPacket[9]=17;
            BinaryPrimitives.WriteUInt16BigEndian(stunPacket.AsSpan(2),68);
            BinaryPrimitives.WriteUInt16BigEndian(stunPacket.AsSpan(24),48);
            BinaryPrimitives.WriteUInt16BigEndian(stunPacket.AsSpan(28),1);
            BinaryPrimitives.WriteUInt16BigEndian(stunPacket.AsSpan(30),20);
            BinaryPrimitives.WriteUInt32BigEndian(stunPacket.AsSpan(32),0x2112a442);
            for(int i=36;i<68;i++)stunPacket[i]=(byte)i;
            foreach(int cut in new[]{8,16})
            {
                var pieces=TelegramVoiceTrial.Fragment(stunPacket,cut);
                Assert(pieces.Length==2&&pieces[0].Skip(20).Concat(pieces[1].Skip(20)).SequenceEqual(stunPacket.Skip(20)),"STUN fragment exact reassembly");
                Assert(BinaryPrimitives.ReadUInt16BigEndian(pieces[0].AsSpan(6))==0x2000&&BinaryPrimitives.ReadUInt16BigEndian(pieces[1].AsSpan(6))==cut/8,"STUN fragment offsets");
                Assert(pieces.All(p=>BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(2))==p.Length),"STUN fragment IP lengths");
            }
            stunPacket[32]=0;Assert(TelegramVoiceTrial.Fragment(stunPacket,8).Length==1,"Non-STUN preserved");
            byte[] discovery=new byte[102];discovery[0]=0x45;discovery[9]=17;
            BinaryPrimitives.WriteUInt16BigEndian(discovery.AsSpan(2),102);
            BinaryPrimitives.WriteUInt16BigEndian(discovery.AsSpan(24),82);
            BinaryPrimitives.WriteUInt16BigEndian(discovery.AsSpan(28),1);
            BinaryPrimitives.WriteUInt16BigEndian(discovery.AsSpan(30),70);
            discovery[35]=123;
            byte[] originalDiscovery=(byte[])discovery.Clone();
            byte[] unreachable=QuicEngine.PortUnreachable(discovery,20,false);
            Assert(unreachable.Length==56&&unreachable[9]==1&&unreachable[20]==3&&unreachable[21]==3&&unreachable.AsSpan(28).SequenceEqual(discovery.AsSpan(0,28)),"IPv4 QUIC fallback quotes exact IP and UDP headers");
            byte[] discordProbe=DiscordVoiceEngine.CreateProbe(discovery,20,false);
            Assert(discordProbe.Length==1228&&BinaryPrimitives.ReadUInt16BigEndian(discordProbe.AsSpan(2))==1228&&BinaryPrimitives.ReadUInt16BigEndian(discordProbe.AsSpan(24))==1208,"Discord IPv4 probe lengths");
            Assert(discovery.SequenceEqual(originalDiscovery)&&discordProbe.AsSpan(12,12).SequenceEqual(discovery.AsSpan(12,12)),"Discord original and endpoint preserved");
            byte[] discovery6=new byte[122];discovery6[0]=0x60;discovery6[6]=17;discovery.AsSpan(20).CopyTo(discovery6.AsSpan(40));
            byte[] probe6=DiscordVoiceEngine.CreateProbe(discovery6,40,true);
            byte[] unreachable6=QuicEngine.PortUnreachable(probe6,40,true);
            Assert(unreachable6.Length==1280&&unreachable6[6]==58&&unreachable6[40]==1&&unreachable6[41]==4&&unreachable6.AsSpan(48).SequenceEqual(probe6.AsSpan(0,1232)),"IPv6 QUIC fallback MTU and original packet quote");
            Assert(probe6.Length==1248&&BinaryPrimitives.ReadUInt16BigEndian(probe6.AsSpan(4))==1208&&BinaryPrimitives.ReadUInt16BigEndian(probe6.AsSpan(44))==1208,"Discord IPv6 probe lengths");
            var fragments=DiscordVoiceEngine.Fragment(discovery);
            Assert(fragments.Length==2&&fragments[0].Length==36&&fragments[1].Length==86,"Discord discovery fragment sizes");
            Assert(fragments[0].AsSpan(20).ToArray().Concat(fragments[1].Skip(20)).SequenceEqual(discovery.Skip(20)),"Discord UDP reassembly preserves datagram");
            Assert(BinaryPrimitives.ReadUInt16BigEndian(fragments[0].AsSpan(6))==0x2000&&BinaryPrimitives.ReadUInt16BigEndian(fragments[1].AsSpan(6))==2,"Discord IPv4 fragment offsets");
            discovery[28]=0xff;Assert(DiscordVoiceEngine.Fragment(discovery).Length==1,"Non-discovery UDP preserved");
            byte[] dns=DnsWire.Query("example.com");Assert(DnsWire.Question(dns)?.Name=="example.com","DNS query parse");
            byte[] dnsAnswer=dns.Concat(new byte[]{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,74,125,8,170}).ToArray();dnsAnswer[2]=0x81;dnsAnswer[3]=0x80;dnsAnswer[7]=1;
            Assert(DnsWire.AddressAnswers(dnsAnswer).SequenceEqual(new[]{"74.125.8.170"}),"Compressed DNS IPv4 CDN discovery");
            for(int length=0;length<dnsAnswer.Length;length++)DnsWire.AddressAnswers(dnsAnswer[..length]);
            Assert(VideoEndpoints.IsVideoHost("rr1---sn-example.googlevideo.com")&&VideoEndpoints.IsVideoHost("rr1---sn-example.c.youtube.com")&&VideoEndpoints.IsVideoHost("manifest.googlevideo.com")&&!VideoEndpoints.IsVideoHost("rr1---sn-example.googlevideo.com.attacker.example"),"Video route host boundary and alias");
            var dnsFailure=DnsWire.Failure(dns);Assert(DnsWire.Matches(dns,dnsFailure)&&(dnsFailure[3]&15)==2,"DNS SERVFAIL fallback");
            Assert(DnsWire.Private(DnsWire.Question(DnsWire.Query("printer.local"))!),"Private DNS preserved");
            Assert(DnsWire.Private(DnsWire.Question(DnsWire.Query("1.0.168.192.in-addr.arpa",12))!),"Private reverse DNS preserved");
            Assert(!DnsWire.Private(DnsWire.Question(DnsWire.Query("8.8.8.8.in-addr.arpa",12))!),"Public reverse DNS uses DoH");
            for(int length=0;length<dns.Length;length++)DnsWire.Question(dns.AsSpan(0,length));
            using(var ctr=new AesCounter(Convert.FromHexString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")))
                Assert(Convert.ToHexString(ctr.Transform(Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a"))).Equals("601ec313775789a5b7a7f504bbf3d228",StringComparison.OrdinalIgnoreCase),"NIST AES256 CTR vector");
            var transport=TelegramTransport.CreateInit(0xefefefef,2);
            using(transport.Tx)using(transport.Rx)Assert(TelegramTransport.IsObfuscated(transport.Init,out int dc)&&dc==2,"Telegram obfuscation init");
            var keys=QuicInitial.Keys(Convert.FromHexString("8394c8f03e515708"));
            Assert(Convert.ToHexString(keys.Key).Equals("1f369613dd76d5467730efcbe3b1a22d",StringComparison.OrdinalIgnoreCase),"RFC9001 client key vector");
            Assert(Convert.ToHexString(keys.Iv).Equals("fa044b2f42a3fd3b46fb255c",StringComparison.OrdinalIgnoreCase),"RFC9001 client IV vector");
            Assert(Convert.ToHexString(keys.Hp).Equals("9f50449e04a0e810283a1e9933adedd2",StringComparison.OrdinalIgnoreCase),"RFC9001 client HP vector");
            byte[] quic=QuicInitial.Create();Assert(quic.Length==1200,"QUIC minimum datagram size");
            var generated=QuicInitial.Keys(quic.AsSpan(6,8).ToArray());
            using(var aes=System.Security.Cryptography.Aes.Create())
            {
                aes.Key=generated.Hp;byte[] mask=aes.EncryptEcb(quic.AsSpan(22,16),System.Security.Cryptography.PaddingMode.None);
                quic[0]^=(byte)(mask[0]&15);for(int i=0;i<4;i++)quic[18+i]^=mask[i+1];
            }
            byte[] plain=new byte[1162];
            using(var gcm=new System.Security.Cryptography.AesGcm(generated.Key,16))gcm.Decrypt(generated.Iv,quic.AsSpan(22,1162),quic.AsSpan(1184,16),plain,quic.AsSpan(0,22));
            Assert(plain[0]==6&&plain[1]==0,"QUIC authenticated CRYPTO frame");
            var fake=FakeHello.Create();Assert(TlsFragmenter.FindSni(fake).Length==14,"generated fake Google SNI");
            byte[] name=Encoding.ASCII.GetBytes("test.example.com");
            var data=new List<byte>();
            data.AddRange(new byte[]{22,3,1,0,0,1,0,0,0,3,3});data.AddRange(new byte[32]);
            data.AddRange(new byte[]{0,0,2,0x13,1,1,0});
            int extLength=9+name.Length;
            data.AddRange(new[]{(byte)(extLength>>8),(byte)extLength,(byte)0,(byte)0,(byte)0,(byte)(5+name.Length),(byte)0,(byte)(3+name.Length),(byte)0,(byte)0,(byte)name.Length});data.AddRange(name);
            byte[] hello=data.ToArray();BinaryPrimitives.WriteUInt16BigEndian(hello.AsSpan(3),(ushort)(hello.Length-5));hello[8]=(byte)(hello.Length-9);
            var sni=TlsFragmenter.FindSni(hello);Assert(sni.Length==name.Length,"SNI length");Assert(hello.AsSpan(sni.Offset,sni.Length).SequenceEqual(name),"SNI contents");
            foreach(var mode in new[]{Strategy.RecordSni,Strategy.RecordTiny})
            {
                byte[] joined=TlsFragmenter.Transform(hello,mode).SelectMany(x=>x.Skip(5)).ToArray();Assert(joined.SequenceEqual(hello.Skip(5)),"TLS transcript invariant "+mode);
            }
            foreach(int length in Enumerable.Range(0,hello.Length)) TlsFragmenter.FindSni(hello.AsSpan(0,length));
            byte[] partialRecord=(byte[])hello.Clone();
            BinaryPrimitives.WriteUInt16BigEndian(partialRecord.AsSpan(3),(ushort)(partialRecord.Length+1500-5));
            int extHeader=50;
            int oldExtensionLength=BinaryPrimitives.ReadUInt16BigEndian(partialRecord.AsSpan(extHeader));
            BinaryPrimitives.WriteUInt16BigEndian(partialRecord.AsSpan(extHeader),(ushort)(oldExtensionLength+1500));
            Assert(TlsFragmenter.FindSni(partialRecord).Length==name.Length,"SNI before missing post-quantum extension tail");
            var random=new Random(12); for(int i=0;i<2000;i++){byte[] fuzz=new byte[random.Next(0,2000)];random.NextBytes(fuzz);TlsFragmenter.FindSni(fuzz);}
            byte[] packet=new byte[40+hello.Length];packet[0]=0x45;packet[9]=6;packet[32]=0x50;packet[33]=0x18;BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2),(ushort)packet.Length);BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(24),10000);hello.CopyTo(packet,40);
            var p=Packets.Parse(packet,packet.Length)!;Assert(p.Payload==40,"IPv4 parser");
            byte[] reset=Packets.ResetToClient(packet,p);var resetInfo=Packets.Parse(reset,reset.Length)!;
            Assert(resetInfo.Payload==resetInfo.End&&reset[resetInfo.Tcp+13]==0x14&&BinaryPrimitives.ReadUInt32BigEndian(reset.AsSpan(resetInfo.Tcp+8))==10000+hello.Length,"Video retry reset has ACK, no TLS payload and correct sequence");
            // SNI after a large extension, beyond the first TCP segment. A timed
            // out assembly must still split that prefix without changing TLS bytes.
            byte[] lateHello=new byte[hello.Length+1604];hello.AsSpan(0,52).CopyTo(lateHello);
            BinaryPrimitives.WriteUInt16BigEndian(lateHello.AsSpan(52),21);
            BinaryPrimitives.WriteUInt16BigEndian(lateHello.AsSpan(54),1600);
            hello.AsSpan(52).CopyTo(lateHello.AsSpan(1656));
            BinaryPrimitives.WriteUInt16BigEndian(lateHello.AsSpan(3),(ushort)(lateHello.Length-5));
            BinaryPrimitives.WriteUInt16BigEndian(lateHello.AsSpan(50),(ushort)(extLength+1604));
            int handshakeLength=lateHello.Length-9;
            lateHello[6]=(byte)(handshakeLength>>16);lateHello[7]=(byte)(handshakeLength>>8);lateHello[8]=(byte)handshakeLength;
            Assert(TlsFragmenter.FindSni(lateHello).Length==name.Length,"Late SNI fixture");
            byte[] prefix=Packets.Segment(packet,p,lateHello[..1396],p.Seq);
            var prefixInfo=Packets.Parse(prefix,prefix.Length)!;
            Assert(TlsFragmenter.FindSni(prefix.AsSpan(prefixInfo.Payload)).Length==0&&TlsFragmenter.RecordLength(prefix.AsSpan(prefixInfo.Payload))>1396,"Incomplete ClientHello fixture");
            var tracker=new ClientHelloTracker();
            var head=tracker.Observe("test",0xfffffff0,lateHello.AsSpan(0,1396));
            Assert(!head.Continuation&&head.Host is null,"ClientHello prefix processed immediately without SNI");
            var tail=tracker.Observe("test",unchecked(0xfffffff0u+1396),lateHello.AsSpan(1396));
            Assert(tail.Continuation&&tail.Host=="test.example.com"&&tail.Split>1,"Late SNI found in streaming continuation with sequence wraparound");
            Assert(!tracker.Observe("test",123,"encrypted data"u8).Continuation,"Tracking ends after SNI; application data untouched");
            foreach(int mode in new[]{0,1,2,3,5,6,7,8})
            {
                var parts=Packets.Transform(prefix,prefixInfo,mode);
                Assert(parts.Count>=2,"Timed-out ClientHello keeps bypass enabled");
                byte[] rebuilt=new byte[1396];
                foreach(var part in parts)
                {
                    var piece=Packets.Parse(part,part.Length)!;
                    int offset=unchecked((int)(piece.Seq-prefixInfo.Seq));
                    for(int j=piece.Payload;j<piece.End;j++)
                    {
                        int target=offset+j-piece.Payload;
                        if(target>=0&&target<rebuilt.Length)rebuilt[target]=part[j];
                    }
                }
                Assert(rebuilt.SequenceEqual(lateHello.Take(1396)),"Timed-out ClientHello prefix stream preserved");
            }
            Assert(Packets.Transform(prefix,prefixInfo,4).Single().SequenceEqual(prefix),"Explicit passthrough stays unchanged");
            // A continuation has no TLS record header. The explicit SNI split
            // must still be honored by both video strategies.
            byte[] tailPacket=Packets.Segment(packet,p,lateHello[1396..],unchecked(p.Seq+1396));
            var tailInfo=Packets.Parse(tailPacket,tailPacket.Length)!;
            foreach(int mode in new[]{7,8})
            {
                var real=Packets.Transform(tailPacket,tailInfo,mode,tail.Split).Skip(6).Select(b=>Packets.Parse(b,b.Length)!).ToArray();
                Assert(real.Any(x=>unchecked(x.Seq-tailInfo.Seq)==tail.Split),"Video continuation splits at tracked SNI");
                byte[] latePacket=Packets.Segment(packet,p,lateHello,p.Seq);
                var lateInfo=Packets.Parse(latePacket,latePacket.Length)!;
                Assert(Packets.Transform(latePacket,lateInfo,mode).All(x=>x.Length<=1400),"Late SNI video MTU bound");
            }
            Assert(PacketEngine.StrategyKey("cdn.example","1.1.1.1")!=PacketEngine.StrategyKey("cdn.example","2.2.2.2"),"Independent CDN endpoint strategy keys");
            for(int mode=0;mode<9;mode++)
            {
                var parts=Packets.Transform(packet,p,mode);var rebuilt=new byte[hello.Length];
                foreach(var part in parts)
                {
                    var info=Packets.Parse(part,part.Length)!;var payload=part.AsSpan(info.Payload,info.End-info.Payload);
                    int offset=unchecked((int)(info.Seq-p.Seq));
                    for(int j=0;j<payload.Length;j++) if(offset+j>=0&&offset+j<rebuilt.Length)rebuilt[offset+j]=payload[j];
                }
                Assert(rebuilt.SequenceEqual(hello),"TCP reassembly invariant "+mode);
            }
            byte[] ip6=new byte[60+hello.Length];ip6[0]=0x60;ip6[6]=6;ip6[52]=0x50;BinaryPrimitives.WriteUInt16BigEndian(ip6.AsSpan(4),(ushort)(ip6.Length-40));hello.CopyTo(ip6,60);
            Assert(Packets.Parse(ip6,ip6.Length)?.Payload==60,"IPv6 parser");
            packet[6]=0x20;Assert(Packets.Parse(packet,packet.Length)==null,"fragment pass-through");
            foreach(uint sequence in new uint[]{0,1,0xfffffff0})
            {
                byte[] big=new byte[5040];packet.AsSpan(0,40).CopyTo(big);big[6]=0;hello.CopyTo(big,40);
                BinaryPrimitives.WriteUInt16BigEndian(big.AsSpan(2),(ushort)big.Length);
                BinaryPrimitives.WriteUInt32BigEndian(big.AsSpan(24),sequence);
                var original=Packets.Parse(big,big.Length)!;
                foreach(int mode in new[]{0,1,2,3,5,6,7,8})
                {
                    byte[] reconstructed=new byte[5000];
                    foreach(var part in Packets.Transform(big,original,mode))
                    {
                        Assert(part.Length<=1400,"bounded segment size");var parsed=Packets.Parse(part,part.Length)!;
                        int offset=unchecked((int)(parsed.Seq-sequence));
                        for(int j=parsed.Payload;j<parsed.End;j++)
                        {
                            int target=offset+j-parsed.Payload;
                            if(target>=0&&target<reconstructed.Length)reconstructed[target]=part[j];
                        }
                    }
                    Assert(reconstructed.SequenceEqual(big.Skip(40)),"multi-segment and wraparound reassembly");
                }
            }
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"self-test.txt"),"PASS: DNS wire parser and SERVFAIL, private/public reverse DNS, NIST AES256 CTR, Telegram obfuscation init, RFC9001 key/IV/HP vectors, QUIC authenticated decryption, generated fake SNI, partial-record SNI, 2000 malformed inputs, TLS transcript, TCP reassembly all 9 modes, video continuation SNI split, late SNI MTU bounds and sequence wraparound, independent CDN endpoints, IPv4/IPv6, IP fragment pass-through");return 0;
        }
        catch(Exception ex){File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"self-test.txt"),"FAIL "+ex);return 1;}
    }
}

