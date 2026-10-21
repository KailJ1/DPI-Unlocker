using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace DPIUnlocker;
// QUIC v1 Initial packet protection, RFC 9001 section 5 and Appendix A.
// This is a decoy, not a complete QUIC client.
internal static class QuicInitial
{
    public static byte[] Expand(byte[] secret,string label,int length)
    {
        byte[] text=Encoding.ASCII.GetBytes("tls13 "+label);
        byte[] info=new byte[2+1+text.Length+1+1];
        BinaryPrimitives.WriteUInt16BigEndian(info,(ushort)length);info[2]=(byte)text.Length;text.CopyTo(info,3);info[^1]=1;
        return HMACSHA256.HashData(secret,info)[..length];
    }
    public static (byte[] Key,byte[] Iv,byte[] Hp) Keys(byte[] dcid)
    {
        byte[] salt=Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        byte[] initial=HMACSHA256.HashData(salt,dcid);
        byte[] client=Expand(initial,"client in",32);
        return (Expand(client,"quic key",16),Expand(client,"quic iv",12),Expand(client,"quic hp",16));
    }
    public static byte[] Create()
    {
        var dcid=RandomNumberGenerator.GetBytes(8);var keys=Keys(dcid);
        byte[] packet=new byte[1200];packet[0]=0xc3;packet[4]=1;packet[5]=8;dcid.CopyTo(packet,6);
        // Zero-length source CID and token. Length includes 4-byte packet number and tag.
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(16),(ushort)(0x4000|1182));
        byte[] plain=new byte[1162];byte[] hello=FakeHello.Create()[5..];
        plain[0]=6;plain[1]=0; // CRYPTO frame, offset 0
        BinaryPrimitives.WriteUInt16BigEndian(plain.AsSpan(2),(ushort)(0x4000|hello.Length));hello.CopyTo(plain,4);
        using(var gcm=new AesGcm(keys.Key,16))gcm.Encrypt(keys.Iv,plain,packet.AsSpan(22,1162),packet.AsSpan(1184,16),packet.AsSpan(0,22));
        using var aes=Aes.Create();aes.Key=keys.Hp;
        byte[] mask=aes.EncryptEcb(packet.AsSpan(22,16),PaddingMode.None);
        packet[0]^=(byte)(mask[0]&0x0f);for(int i=0;i<4;i++)packet[18+i]^=mask[1+i];
        return packet;
    }
}

