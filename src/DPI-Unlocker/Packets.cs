using System.Buffers.Binary;
using System.Net;
namespace DPIUnlocker;
internal sealed record PacketInfo(int Tcp, int Payload, int End, bool V6, uint Seq, string Flow, string Destination);
internal static class Packets
{
    public static PacketInfo? Parse(byte[] b, int size)
    {
        if (size < 40) return null;
        bool v6 = b[0] >> 4 == 6; int tcp, end; string src, dst;
        if (v6)
        {
            if (b[6] != 6 || size < 60) return null;
            tcp = 40; end = 40 + BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(4));
            src = new IPAddress(b.AsSpan(8, 16)).ToString(); dst = new IPAddress(b.AsSpan(24, 16)).ToString();
        }
        else
        {
            if (b[0] >> 4 != 4 || b[9] != 6 || (BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(6)) & 0x3fff) != 0) return null;
            tcp = (b[0] & 15) * 4; end = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(2));
            if (tcp < 20) return null;
            src = new IPAddress(b.AsSpan(12,4)).ToString(); dst = new IPAddress(b.AsSpan(16,4)).ToString();
        }
        if (end > size || end < tcp + 20) return null;
        int payload = tcp + (b[tcp+12] >> 4)*4;
        if (payload < tcp+20 || payload > end) return null;
        int sp = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(tcp)); int dp = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(tcp+2));
        return new(tcp, payload, end, v6, BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(tcp+4)), $"{src}|{sp}|{dst}|{dp}", dst);
    }
    public static string ReverseFlow(byte[] b, PacketInfo p)
    {
        string src = new IPAddress(b.AsSpan(p.V6 ? 8 : 12, p.V6 ? 16 : 4)).ToString();
        int sp = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p.Tcp)); int dp = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(p.Tcp+2));
        return $"{p.Destination}|{dp}|{src}|{sp}";
    }
    public static byte[] Segment(byte[] original, PacketInfo p, byte[] payload, uint sequence)
    {
        byte[] b = new byte[p.Payload + payload.Length]; original.AsSpan(0,p.Payload).CopyTo(b); payload.CopyTo(b,p.Payload);
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p.Tcp+4),sequence);
        if (p.V6) BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4),(ushort)(b.Length-40));
        else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
        return b;
    }
    internal static byte[] ResetToClient(byte[] original,PacketInfo p)
    {
        byte[] reset=new byte[p.Tcp+20];original.AsSpan(0,p.Tcp).CopyTo(reset);
        int source=p.V6?8:12,target=p.V6?24:16,size=p.V6?16:4;
        for(int i=0;i<size;i++)(reset[source+i],reset[target+i])=(reset[target+i],reset[source+i]);
        original.AsSpan(p.Tcp+2,2).CopyTo(reset.AsSpan(p.Tcp));original.AsSpan(p.Tcp,2).CopyTo(reset.AsSpan(p.Tcp+2));
        original.AsSpan(p.Tcp+8,4).CopyTo(reset.AsSpan(p.Tcp+4));
        BinaryPrimitives.WriteUInt32BigEndian(reset.AsSpan(p.Tcp+8),unchecked(p.Seq+(uint)(p.End-p.Payload)));
        reset[p.Tcp+12]=0x50;reset[p.Tcp+13]=0x14;
        BinaryPrimitives.WriteUInt16BigEndian(reset.AsSpan(p.V6?4:2),(ushort)(reset.Length-(p.V6?40:0)));
        return reset;
    }
    public static byte[] SegmentWithMd5(byte[] original, PacketInfo p, byte[] payload, uint sequence)
    {
        byte[] md5 = new byte[p.Tcp + 40 + payload.Length];
        original.AsSpan(0, p.Tcp + 20).CopyTo(md5);
        BinaryPrimitives.WriteUInt32BigEndian(md5.AsSpan(p.Tcp + 4), sequence);
        md5[p.Tcp + 12] = (byte)(0xa0 | (md5[p.Tcp + 12] & 15));
        md5[p.Tcp + 13] &= 0xf7;
        md5[p.Tcp + 20] = 19;
        md5[p.Tcp + 21] = 18;
        System.Security.Cryptography.RandomNumberGenerator.Fill(md5.AsSpan(p.Tcp + 22, 16));
        md5[p.Tcp + 38] = 1;
        md5[p.Tcp + 39] = 1;
        payload.CopyTo(md5, p.Tcp + 40);
        if (p.V6) BinaryPrimitives.WriteUInt16BigEndian(md5.AsSpan(4), (ushort)(md5.Length - 40));
        else BinaryPrimitives.WriteUInt16BigEndian(md5.AsSpan(2), (ushort)md5.Length);
        return md5;
    }
    public static List<byte[]> Transform(byte[] b, PacketInfo p, int mode, int? splitOffset = null)
    {
        byte[] data = b[p.Payload..p.End];
        if (data.Length < 2 || mode == 4) return [b[..p.End]];
        var sni = TlsFragmenter.FindSni(data);

        int midsld = splitOffset ?? ((sni.Offset > 0 && sni.Length > 0) ? sni.Offset + Math.Max(1, sni.Length / 2) : -1);

        if (mode is 7 or 8)
        {
            // Mode 7 & Mode 8: Fake TLS with SNI substitution and multisplit / multidisorder.
            // Mode 7 uses decoy SNI "www.google.com" with multisplit [seg1, seg2, seg3].
            // Mode 8 uses the same decoy with multidisorder [seg2, seg1, seg3].
            byte[] fake = FakeHello.Create("www.google.com");
            var f = mode == 8
                ? Segment(b, p, fake, unchecked(p.Seq - 10000u))
                : SegmentWithMd5(b, p, fake, unchecked(p.Seq - 10000u));

            List<byte[]> realParts = new();
            if (midsld > 1 && midsld < data.Length)
            {
                var seg1 = Segment(b, p, data[..1], p.Seq);
                seg1[p.Tcp + 13] &= 0xf7;

                List<byte[]> middle = new();
                for(int offset=1;offset<midsld;)
                {
                    int length=Math.Min(1400-p.Payload,midsld-offset);
                    var part=Segment(b,p,data.AsSpan(offset,length).ToArray(),unchecked(p.Seq+(uint)offset));
                    part[p.Tcp+13]&=0xf7;middle.Add(part);offset+=length;
                }

                List<byte[]> seg3List = new();
                for (int offset = midsld; offset < data.Length;)
                {
                    int length = Math.Min(1400 - p.Payload, data.Length - offset);
                    var part = Segment(b, p, data.AsSpan(offset, length).ToArray(), unchecked(p.Seq + (uint)offset));
                    if (offset + length < data.Length) part[p.Tcp + 13] &= 0xf7;
                    seg3List.Add(part);
                    offset += length;
                }

                if (mode == 8)
                {
                    realParts.AddRange(middle);
                    realParts.Add(seg1);
                    realParts.AddRange(seg3List);
                }
                else
                {
                    realParts.Add(seg1);
                    realParts.AddRange(middle);
                    realParts.AddRange(seg3List);
                }
            }
            else
            {
                int fallbackCut = 1;
                var fallbackFirst = Segment(b, p, data[..fallbackCut], p.Seq);
                fallbackFirst[p.Tcp + 13] &= 0xf7;
                realParts.Add(fallbackFirst);
                for (int offset = fallbackCut; offset < data.Length;)
                {
                    int length = Math.Min(1400 - p.Payload, data.Length - offset);
                    var part = Segment(b, p, data.AsSpan(offset, length).ToArray(), unchecked(p.Seq + (uint)offset));
                    if (offset + length < data.Length) part[p.Tcp + 13] &= 0xf7;
                    realParts.Add(part);
                    offset += length;
                }
            }

            if (!p.V6)
            {
                f[4] = 0; f[5] = 0;
                foreach (var part in realParts) { part[4] = 0; part[5] = 0; }
            }

            return [f, f, f, f, f, f, ..realParts];
        }

        int cut = splitOffset ?? (mode is 2 ? 1 : sni.Offset > 0 ? sni.Offset + Math.Max(1, sni.Length / 2) : 1);
        cut = Math.Min(cut, Math.Min(data.Length - 1, 1400 - p.Payload));
        var first = Segment(b, p, data[..cut], p.Seq);
        var rest = new List<byte[]>();
        for (int offset = cut; offset < data.Length;)
        {
            int length = Math.Min(1400 - p.Payload, data.Length - offset);
            var part = Segment(b, p, data.AsSpan(offset, length).ToArray(), unchecked(p.Seq + (uint)offset));
            if (offset + length < data.Length) part[p.Tcp + 13] &= 0xf7;
            rest.Add(part); offset += length;
        }
        first[p.Tcp + 13] &= 0xf7;
        if (mode == 2)
        {
            int n = Math.Min(681, 1400 - p.Payload - cut);
            if (n > 0)
            {
                var overlap = new byte[n + cut]; byte[] pattern = FakeHello.Create();
                for (int i = 0; i < n; i++) overlap[i] = pattern[i % pattern.Length];
                data.AsSpan(0, cut).CopyTo(overlap.AsSpan(n));
                first = Segment(b, p, overlap, unchecked(p.Seq - (uint)n)); first[p.Tcp + 13] &= 0xf7;
            }
            if (!p.V6) foreach (var part in new[] { first }.Concat(rest)) { part[4] = 0; part[5] = 0; }
        }
        if (mode is 1 or 5 or 6)
        {
            byte[] fake = FakeHello.Create();
            var f = Segment(b, p, fake, unchecked(p.Seq - (mode == 1 ? 0x40000000u : 10000u)));
            if (mode is 5)
            {
                f = SegmentWithMd5(b, p, fake, unchecked(p.Seq - 10000u));
            }
            return [f, first, ..rest];
        }
        return mode == 3 ? [..rest, first] : [first, ..rest];
    }
}

