using System.Text.RegularExpressions;
namespace DPIUnlocker;
internal static class TelegramRelayPool
{
    private static readonly SemaphoreSlim gate=new(1,1);
    private static string[]? domains;
    public static async Task<string[]> Get(CancellationToken ct)
    {
        if(domains is not null)return domains;
        await gate.WaitAsync(ct);
        try
        {
            if(domains is not null)return domains;
            string cache=Path.Combine(Program.DataDir,"telegram-relays.txt"),text="";
            try
            {
                using var handler=new SocketsHttpHandler{UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(3)};
                using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(5)};
                text=await client.GetStringAsync("https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt",ct);
            }
            catch(HttpRequestException){}catch(OperationCanceledException)when(!ct.IsCancellationRequested){}
            if(text.Length==0&&File.Exists(cache))text=File.ReadAllText(cache);
            var parsed=text.Split(['\r','\n'],StringSplitOptions.RemoveEmptyEntries).Select(s=>Decode(s.Trim())).Where(s=>s.Length<200&&Regex.IsMatch(s,"^[a-z0-9][a-z0-9.-]+\\.[a-z]{2,}$")).Distinct().Take(64).ToArray();
            if(parsed.Length>0){domains=parsed;Directory.CreateDirectory(Program.DataDir);File.WriteAllText(cache,text);return domains;}
            return [];
        }
        finally{gate.Release();}
    }
    private static string Decode(string s)
    {
        if(!s.EndsWith(".com",StringComparison.Ordinal))return s;
        string stem=s[..^4];int shift=stem.Count(char.IsAsciiLetter);
        return new string(stem.Select(c=>c is >= 'a' and <= 'z'?(char)('a'+(c-'a'-shift%26+26)%26):c).ToArray())+".co.uk";
    }
}

