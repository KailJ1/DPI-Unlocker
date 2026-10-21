using System.Buffers.Binary;
namespace DPIUnlocker;
internal enum Strategy { Direct, RecordSni, TcpSni, RecordTiny }
internal static class TlsFragmenter
{
    public static int RecordLength(ReadOnlySpan<byte> data) => data.Length >= 5 && data[0] == 22 && data[1] == 3 ? 5 + BinaryPrimitives.ReadUInt16BigEndian(data[3..]) : 0;
    public static (int Offset, int Length) FindSni(ReadOnlySpan<byte> b)
    {
        try
        {
            int limit = RecordLength(b);
            if (limit == 0 || b.Length < 44 || b[5] != 1) return default;
            int p = 43;
            p += 1 + b[p];
            int ciphers = BinaryPrimitives.ReadUInt16BigEndian(b[p..]); p += 2 + ciphers;
            p += 1 + b[p];
            int end = p + 2 + BinaryPrimitives.ReadUInt16BigEndian(b[p..]); p += 2;
            if (end > limit) return default;
            // SNI can be complete in the first TCP segment even when a large
            // post-quantum key share later in this record has not arrived yet.
            end = Math.Min(end,b.Length);
            while (p + 4 <= end)
            {
                int type = BinaryPrimitives.ReadUInt16BigEndian(b[p..]);
                int size = BinaryPrimitives.ReadUInt16BigEndian(b[(p + 2)..]); p += 4;
                if (p + size > end) return default;
                if (type == 0 && size >= 5)
                {
                    int listEnd = p + 2 + BinaryPrimitives.ReadUInt16BigEndian(b[p..]);
                    if (listEnd > p + size) return default;
                    int q = p + 2;
                    while (q + 3 <= listEnd)
                    {
                        int kind = b[q]; int n = BinaryPrimitives.ReadUInt16BigEndian(b[(q + 1)..]); q += 3;
                        if (q + n > listEnd) return default;
                        if (kind == 0 && n > 0) return (q, n);
                        q += n;
                    }
                }
                p += size;
            }
        }
        catch (ArgumentOutOfRangeException) { }
        catch (IndexOutOfRangeException) { }
        return default;
    }
    public static List<byte[]> Transform(byte[] hello, Strategy strategy)
    {
        int end = RecordLength(hello);
        if (end == 0 || end != hello.Length || strategy == Strategy.Direct) return [hello];
        var (offset, length) = FindSni(hello);
        int split = offset > 0 ? offset + Math.Max(1, length / 2) : Math.Min(hello.Length - 1, 48);
        if (strategy == Strategy.TcpSni) return [hello[..split], hello[split..]];
        var cuts = strategy == Strategy.RecordTiny ? new[] { 6, Math.Max(7, split), end } : new[] { Math.Max(6, split), end };
        var output = new List<byte[]>(); int previous = 5;
        foreach (int cut in cuts.Distinct().Order())
        {
            if (cut <= previous || cut > end) continue;
            var record = new byte[5 + cut - previous]; hello.AsSpan(0, 3).CopyTo(record);
            BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), (ushort)(cut - previous));
            hello.AsSpan(previous, cut - previous).CopyTo(record.AsSpan(5));
            output.Add(record); previous = cut;
        }
        return output;
    }
}

