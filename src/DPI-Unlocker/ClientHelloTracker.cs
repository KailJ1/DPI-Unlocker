using System.Text;
namespace DPIUnlocker;

// Observe copies of fragmented hellos; never hold packets waiting for their tail.
internal sealed class ClientHelloTracker
{
    private sealed record Prefix(uint Sequence,int Expected,DateTime Created,List<byte> Data);
    private readonly Dictionary<string,Prefix> prefixes=new();
    internal readonly record struct Part(bool Continuation,string? Host,int Split);
    internal Part Observe(string flow,uint sequence,ReadOnlySpan<byte> data)
    {
        bool hello=data.Length>5&&data[0]==22&&data[1]==3&&data[5]==1;
        if(hello)
        {
            prefixes.Remove(flow);
            var sni=TlsFragmenter.FindSni(data);
            if(sni.Length>0)return new(false,Encoding.ASCII.GetString(data.Slice(sni.Offset,sni.Length)),sni.Offset+sni.Length/2);
            int expected=TlsFragmenter.RecordLength(data);
            if(expected>data.Length&&expected<=18437&&prefixes.Count<256)
                prefixes[flow]=new(sequence,expected,DateTime.UtcNow,new(data.ToArray()));
            return default;
        }
        if(!prefixes.TryGetValue(flow,out var prefix))return default;
        if(DateTime.UtcNow-prefix.Created>TimeSpan.FromSeconds(10)){prefixes.Remove(flow);return default;}
        int previous=prefix.Data.Count;
        if(sequence!=unchecked(prefix.Sequence+(uint)previous))return default;
        prefix.Data.AddRange(data[..Math.Min(data.Length,prefix.Expected-previous)].ToArray());
        byte[] joined=prefix.Data.ToArray();var found=TlsFragmenter.FindSni(joined);
        if(found.Length>0)
        {
            prefixes.Remove(flow);
            return new(true,Encoding.ASCII.GetString(joined,found.Offset,found.Length),Math.Clamp(found.Offset+found.Length/2-previous,1,Math.Max(1,data.Length-1)));
        }
        if(prefix.Data.Count>=prefix.Expected)prefixes.Remove(flow);
        return new(true,null,1);
    }
    internal void Trim()
    {
        foreach(var key in prefixes.Where(x=>DateTime.UtcNow-x.Value.Created>TimeSpan.FromSeconds(10)).Select(x=>x.Key).ToArray())prefixes.Remove(key);
    }
}
