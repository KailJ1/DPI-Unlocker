using System.Net;
using System.Net.Sockets;
using System.Text.Json;
namespace DPIUnlocker;
internal static class TelegramWebTest
{
    public static async Task<int> Run()
    {
        var checks=from host in new[]{"web.telegram.org","t.me","telegram.org"} from ip in new[]{"149.154.167.99","149.154.167.220"} select(host,ip);
        var results=await Task.WhenAll(checks.Select(async check=>
        {
            using var handler=new SocketsHttpHandler{UseProxy=false,AllowAutoRedirect=false,ConnectTimeout=TimeSpan.FromSeconds(3)};
            handler.ConnectCallback=async(_,ct)=>{var socket=new Socket(SocketType.Stream,ProtocolType.Tcp){NoDelay=true};try{await socket.ConnectAsync(IPAddress.Parse(check.ip),443,ct);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}};
            using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(6)};
            try{using var response=await client.GetAsync("https://"+check.host+"/");return new{check.host,check.ip,status=(int)response.StatusCode,bytes=(await response.Content.ReadAsByteArrayAsync()).Length,error=""};}
            catch(Exception ex){return new{check.host,check.ip,status=0,bytes=0,error=ex.GetBaseException().Message};}
        }));
        File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"telegram-web-test.json"),JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));return 0;
    }
}

