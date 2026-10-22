using System.Runtime.InteropServices;
using System.Text;
namespace DPIUnlocker;

// Preserve every byte outside this module's explicitly marked block.
internal static class AiHostsFile
{
    private const string Begin="# BEGIN DPI-Unlocker Smart DNS";
    private const string End="# END DPI-Unlocker Smart DNS";
    private const string Separator="# DPI-Unlocker added preceding newline";
    internal static string PathName=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"drivers","etc","hosts");
    internal static byte[] Merge(byte[] original,IReadOnlyDictionary<string,string[]> entries)
    {
        byte[] begin=Encoding.ASCII.GetBytes(Begin),end=Encoding.ASCII.GetBytes(End);
        int start=original.AsSpan().IndexOf(begin);
        byte[] clean=original;
        if(start>=0)
        {
            if(start>0&&original[start-1]!=10)throw new IOException("Некорректная метка Smart DNS в hosts");
            int finish=original.AsSpan(start+begin.Length).IndexOf(end);
            if(finish<0)throw new IOException("Не найдена конечная метка Smart DNS в hosts; файл не изменён");
            finish+=start+begin.Length+end.Length;
            if(finish<original.Length&&original[finish]==13)finish++;
            if(finish<original.Length&&original[finish]==10)finish++;
            bool removeSeparator=original.AsSpan(start,finish-start).IndexOf(Encoding.ASCII.GetBytes(Separator))>=0;
            if(removeSeparator&&start>=2&&original[start-2]==13&&original[start-1]==10)start-=2;
            clean=original.AsSpan(0,start).ToArray().Concat(original.AsSpan(finish).ToArray()).ToArray();
            if(clean.AsSpan().IndexOf(begin)>=0)throw new IOException("Повторная метка Smart DNS в hosts; файл не изменён");
        }
        if(entries.Count==0)return clean;
        var block=new StringBuilder();
        bool addSeparator=clean.Length>0&&clean[^1]!=10;
        if(addSeparator)block.Append("\r\n");
        block.Append(Begin).Append("\r\n");
        if(addSeparator)block.Append(Separator).Append("\r\n");
        foreach(var entry in entries.OrderBy(x=>x.Key,StringComparer.Ordinal))
        {
            // Hosts files cannot express wildcard names. Only the validated exact names are written.
            if(Uri.CheckHostName(entry.Key)!=UriHostNameType.Dns)throw new InvalidDataException("Недопустимое имя Smart DNS");
            foreach(string ip in entry.Value)
            {
                if(!System.Net.IPAddress.TryParse(ip,out var address)||address.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)throw new InvalidDataException("Недопустимый адрес Smart DNS");
                block.Append(ip).Append(' ').Append(entry.Key).Append("\r\n");
            }
        }
        block.Append(End).Append("\r\n");return clean.Concat(Encoding.ASCII.GetBytes(block.ToString())).ToArray();
    }
    [DllImport("dnsapi.dll")][return:MarshalAs(UnmanagedType.Bool)]private static extern bool DnsFlushResolverCache();
    internal static void Apply(IReadOnlyDictionary<string,string[]> entries)
    {
        using var file=new FileStream(PathName,FileMode.Open,FileAccess.ReadWrite,FileShare.Read);
        if(file.Length>4_000_000)throw new IOException("Файл hosts слишком большой");
        byte[] before=new byte[file.Length];file.ReadExactly(before);byte[] after=Merge(before,entries);
        if(before.AsSpan().SequenceEqual(after))return;
        file.Position=0;file.Write(after);file.SetLength(after.Length);file.Flush(true);DnsFlushResolverCache();
    }
    internal static void Cleanup()=>Apply(new Dictionary<string,string[]>());
}

internal sealed class AiHosts(AiRoutes routes,int provider)
{
    internal async Task Run(Action<string> log,CancellationToken ct)
    {
        using var resolver=new AiDnsResolver(provider);resolver.Log+=log;
        var addresses=new System.Collections.Concurrent.ConcurrentDictionary<string,string[]>(StringComparer.OrdinalIgnoreCase);
        try
        {
            while(!ct.IsCancellationRequested)
            {
                await Task.WhenAll(routes.Hosts.Select(async host=>
                {
                    try
                    {
                        byte[] answer=await resolver.Resolve(DnsWire.Query(host),ct);string[] ips=DnsWire.AddressAnswers(answer).ToArray();
                        if(ips.Length==0)throw new IOException("Smart DNS не вернул IPv4-адрес");
                        addresses[host]=ips;routes.Observe(answer);
                    }
                    catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
                    catch(Exception ex){log("AI_HOSTS_FAIL "+host+" "+ex.GetBaseException().Message);}
                }));
                if(ct.IsCancellationRequested)break;
                if(routes.Hosts.Any(host=>!addresses.ContainsKey(host)))log("AI_HOSTS_INCOMPLETE: часть выбранных доменов не получила адрес Smart DNS");
                AiHostsFile.Apply(addresses);
                log("AI_HOSTS_READY: адресов для доменов="+addresses.Count+"; обновление раз в минуту; прокси не настраивается");
                await Task.Delay(TimeSpan.FromMinutes(1),ct);
            }
        }
        finally{AiHostsFile.Cleanup();log("AI_HOSTS_REMOVED: записи Smart DNS удалены");}
    }
}
