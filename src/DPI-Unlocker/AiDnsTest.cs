using System.Net;
using System.Net.Sockets;
namespace DPIUnlocker;
internal static class AiDnsTest
{
    internal static async Task<int> Run()
    {
        var results=new List<object>();int successes=0;
        using var resolver=new AiDnsResolver(1);using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(40));
        foreach(string host in new[]{"gemini.google.com","chatgpt.com","claude.ai"})
        {
            try
            {
                byte[] q=DnsWire.Query(host),answer=await resolver.Resolve(q,timeout.Token);
                if(answer[0]!=q[0]||answer[1]!=q[1])throw new IOException("DNS transaction ID mismatch");
                string[] addresses=DnsWire.AddressAnswers(answer).ToArray();if(addresses.Length==0)throw new IOException("No Smart DNS IPv4 answer");
                var handler=new SocketsHttpHandler(){UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(6)};
                handler.ConnectCallback=async(_,ct)=>
                {
                    var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                    try{await socket.ConnectAsync(IPAddress.Parse(addresses[0]),443,ct);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}
                };
                using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(12)};
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
                client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                using var response=await client.GetAsync("https://"+host+(host.StartsWith("gemini")?"/app":"/"),HttpCompletionOption.ResponseHeadersRead,timeout.Token);
                results.Add(new{host,addresses,proxy=false,certificateValidation=true,status=(int)response.StatusCode});successes++;
            }
            catch(Exception ex){results.Add(new{host,error=ex.GetBaseException().Message});}
        }
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"smartdns-test.json"),System.Text.Json.JsonSerializer.Serialize(results,new System.Text.Json.JsonSerializerOptions{WriteIndented=true}));
        return successes==2?0:1;
    }
}
