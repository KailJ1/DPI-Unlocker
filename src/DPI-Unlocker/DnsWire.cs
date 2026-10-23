using System.Buffers.Binary;
using System.Text;
namespace DPIUnlocker;
internal sealed record DnsQuestion(string Name,ushort Type,ushort Class,int End);
internal static class DnsWire
{
    internal static byte[] AddressAnswer(byte[] query,string? address,uint ttl=60)
    {
        var q=Question(query)??throw new InvalidDataException("Invalid DNS question");
        byte[] answer=new byte[q.End+(address is null?0:16)];query.AsSpan(0,q.End).CopyTo(answer);
        BinaryPrimitives.WriteUInt16BigEndian(answer.AsSpan(2),(ushort)(0x8080|(BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2))&0x0100)));Array.Clear(answer,6,6);
        if(address is not null)
        {
            byte[] ip=System.Net.IPAddress.Parse(address).GetAddressBytes();if(ip.Length!=4||q.Type!=1)throw new InvalidDataException("Expected IPv4 A answer");
            answer[7]=1;int p=q.End;
            new byte[]{0xc0,0x0c,0,1,0,1,0,0,0,0,0,4}.CopyTo(answer,p);
            BinaryPrimitives.WriteUInt32BigEndian(answer.AsSpan(p+6),ttl);ip.CopyTo(answer,p+12);
        }
        return answer;
    }
    internal static List<string> AddressAnswers(byte[] answer)
    {
        var ips=new List<string>();var q=Question(answer);if(q is null||answer.Length<12)return ips;
        int p=q.End,count=Math.Min(128,(int)BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(6)));
        for(int i=0;i<count;i++)
        {
            bool nameEnd=false;
            while(p<answer.Length)
            {
                int n=answer[p++];if(n==0){nameEnd=true;break;}
                if((n&0xc0)==0xc0){if(p>=answer.Length)return ips;p++;nameEnd=true;break;}
                if(n>63||p+n>answer.Length)return ips;p+=n;
            }
            if(!nameEnd||p+10>answer.Length)return ips;
            int type=BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(p)),klass=BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(p+2)),length=BinaryPrimitives.ReadUInt16BigEndian(answer.AsSpan(p+8));p+=10;
            if(p+length>answer.Length)return ips;
            if(type==1&&klass==1&&length==4)ips.Add(new System.Net.IPAddress(answer.AsSpan(p,4)).ToString());
            p+=length;
        }
        return ips;
    }
    public static DnsQuestion? Question(ReadOnlySpan<byte> data)
    {
        if(data.Length<17||BinaryPrimitives.ReadUInt16BigEndian(data[4..])!=1)return null;
        int p=12;var labels=new List<string>();
        while(p<data.Length)
        {
            int n=data[p++];if(n==0)break;
            if(n>63||p+n>data.Length||labels.Count>127)return null;
            labels.Add(Encoding.ASCII.GetString(data.Slice(p,n)));p+=n;
        }
        if(p+4>data.Length||labels.Count==0)return null;
        string name=string.Join('.',labels);if(name.Length>253)return null;
        return new(name,BinaryPrimitives.ReadUInt16BigEndian(data[p..]),BinaryPrimitives.ReadUInt16BigEndian(data[(p+2)..]),p+4);
    }
    public static bool Private(DnsQuestion q)
    {
        string name=q.Name.ToLowerInvariant();
        if(!name.Contains('.')||name.EndsWith(".local")||name.EndsWith(".lan")||name.EndsWith(".home.arpa"))return true;
        if(name.EndsWith(".in-addr.arpa"))
        {
            string ip=string.Join('.',name[..^13].Split('.').Reverse());
            if(System.Net.IPAddress.TryParse(ip,out var address))
            {
                var b=address.GetAddressBytes();return b.Length==4&&(b[0] is 10 or 127||b[0]==192&&b[1]==168||b[0]==172&&b[1] is >=16 and <=31||b[0]==169&&b[1]==254);
            }
        }
        return name.EndsWith(".ip6.arpa");
    }
    public static byte[] Query(string name,ushort type=1)
    {
        var b=new List<byte>(new byte[12]);b[0]=0x12;b[1]=0x34;b[2]=1;b[5]=1;
        foreach(string label in name.TrimEnd('.').Split('.')){if(label.Length is <1 or >63)throw new ArgumentException("DNS label length");b.Add((byte)label.Length);b.AddRange(Encoding.ASCII.GetBytes(label));}
        b.AddRange(new byte[]{0,(byte)(type>>8),(byte)type,0,1});return b.ToArray();
    }
    public static byte[] Failure(byte[] query)
    {
        var q=Question(query);byte[] result=query[..(q?.End??Math.Min(query.Length,12))];if(result.Length<12)return [];
        ushort flags=(ushort)((BinaryPrimitives.ReadUInt16BigEndian(query.AsSpan(2))&0x7900)|0x8082);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(2),flags);Array.Clear(result,6,6);return result;
    }
    public static bool Matches(byte[] query,byte[] answer)
    {
        var q=Question(query);var a=Question(answer);
        return q is not null&&a is not null&&answer.Length>=12&&(answer[2]&0x80)!=0&&q.Type==a.Type&&q.Class==a.Class&&q.Name.Equals(a.Name,StringComparison.OrdinalIgnoreCase);
    }
}

