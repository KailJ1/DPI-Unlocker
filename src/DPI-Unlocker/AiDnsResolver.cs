using System.Net.Http.Headers;
using System.Net;
using System.Net.Sockets;
namespace DPIUnlocker;

// Only DNS uses this client. The browser retains its original hostname and TLS session.
internal sealed class AiDnsResolver:IDisposable
{
    internal static readonly string[] Endpoints=["https://dns.zapret.moe/dns-query","https://dns.comss.one/dns-query","https://dns.geohide.ru/dns-query"];
    private readonly HttpClient client=new(new SocketsHttpHandler(){UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(3),PooledConnectionLifetime=TimeSpan.FromMinutes(5),MaxConnectionsPerServer=8}){Timeout=TimeSpan.FromSeconds(8)};
    private readonly int selection;
    private int active;
    private readonly HttpClient geoClient;
    private static readonly SemaphoreSlim geminiGate=new(1,1);
    private static string? geminiAddress;
    private static DateTime geminiVerified;
    internal AiDnsResolver(int provider=0)
    {
        if(provider is <0 or >3)throw new ArgumentOutOfRangeException(nameof(provider));
        selection=provider;active=provider==0?2:provider-1;
        var handler=new SocketsHttpHandler(){UseProxy=false,PooledConnectionLifetime=TimeSpan.FromMinutes(5),MaxConnectionsPerServer=8};
        // Verified GeoHide EU resolver addresses; retain the DNS name for TLS certificate validation.
        handler.ConnectCallback=async(_,ct)=>
        {
            foreach(string ip in new[]{"143.20.64.192","45.13.237.213"})
            {
                var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                try{using var limit=CancellationTokenSource.CreateLinkedTokenSource(ct);limit.CancelAfter(TimeSpan.FromSeconds(3));await socket.ConnectAsync(IPAddress.Parse(ip),443,limit.Token);return new NetworkStream(socket,true);}
                catch(Exception ex)when(ex is SocketException or OperationCanceledException){socket.Dispose();ct.ThrowIfCancellationRequested();}
            }
            throw new IOException("GeoHide EU DNS недоступен");
        };
        geoClient=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(8)};
    }
    internal event Action<string>? Log;
    internal async Task<byte[]> Resolve(byte[] original,CancellationToken ct)
    {
        int first=Volatile.Read(ref active);
        for(int attempt=0;attempt<(selection==0?Endpoints.Length:1);attempt++)
        {
            int index=(first+attempt)%Endpoints.Length;
            try
            {
                var question=DnsWire.Question(original)??throw new IOException("Invalid Smart DNS query");
                if(index==2&&question.Class==1&&AiRoutes.IsGeminiHost(question.Name))
                {
                    if(question.Type is 28 or 64 or 65)return DnsWire.AddressAnswer(original,null);
                    if(question.Type==1)
                    {
                        string ip=await GeminiAddress(ct);
                        Interlocked.Exchange(ref active,index);
                        Log?.Invoke("AI_DNS "+question.Name+" provider=GeoHide-EU validated="+ip);
                        return DnsWire.AddressAnswer(original,ip);
                    }
                }
                byte[] answer=await Query(original,index,ct);
                Interlocked.Exchange(ref active,index);
                Log?.Invoke("AI_DNS "+question.Name+" provider="+new Uri(Endpoints[index]).Host);
                return answer;
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
            catch(Exception ex)when(ex is IOException or HttpRequestException or OperationCanceledException)
            {Log?.Invoke("AI_DNS_ENDPOINT_FAIL "+new Uri(Endpoints[index]).Host+" "+ex.GetBaseException().Message);}
        }
        throw new IOException("Smart DNS недоступен. Переключите сервер Smart DNS или снимите галочку сервиса.");
    }
    private async Task<byte[]> Query(byte[] original,int index,CancellationToken ct)
    {
                using var request=new HttpRequestMessage(HttpMethod.Post,Endpoints[index]);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                request.Content=new ByteArrayContent(original);request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/dns-message");
                using var response=await (index==2?geoClient:client).SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);response.EnsureSuccessStatusCode();
                if(response.Content.Headers.ContentType?.MediaType!="application/dns-message")throw new IOException("Unexpected Smart DNS media type");
                using var body=await response.Content.ReadAsStreamAsync(ct);using var output=new MemoryStream();
                byte[] buffer=new byte[8192];int read;
                while((read=await body.ReadAsync(buffer,ct))!=0){if(output.Length+read>65507)throw new IOException("Smart DNS response too large");output.Write(buffer,0,read);}
                byte[] answer=output.ToArray();if(!DnsWire.Matches(original,answer)||(answer[3]&15)!=0)throw new IOException("Smart DNS question or response mismatch");
                answer[0]=original[0];answer[1]=original[1];
                return answer;
    }
    private async Task<string> GeminiAddress(CancellationToken ct)
    {
        await geminiGate.WaitAsync(ct);
        try
        {
            if(geminiAddress is not null&&DateTime.UtcNow-geminiVerified<TimeSpan.FromMinutes(5))return geminiAddress;
            byte[] answer=await Query(DnsWire.Query("gemini.google.com"),2,ct);
            string[] addresses=DnsWire.AddressAnswers(answer).Distinct().ToArray();
            // Keep a working egress address rather than rotating a signed-in session every refresh.
            if(geminiAddress is not null&&addresses.Contains(geminiAddress)&&await CheckGemini(geminiAddress,ct) is not null)
            {geminiVerified=DateTime.UtcNow;return geminiAddress;}
            using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);stop.CancelAfter(TimeSpan.FromSeconds(8));
            var probes=addresses.Select(ip=>CheckGemini(ip,stop.Token)).ToList();
            while(probes.Count>0)
            {
                Task<string?> completed=await Task.WhenAny(probes);probes.Remove(completed);
                string? good=await completed;
                if(good is not null)
                {
                    stop.Cancel();await Task.WhenAll(probes);geminiAddress=good;geminiVerified=DateTime.UtcNow;
                    Log?.Invoke("AI_GEMINI_ENDPOINT_READY "+good+" HTTPS validated; redirects rejected");return good;
                }
            }
            ct.ThrowIfCancellationRequested();throw new IOException("Ни один адрес Gemini из Smart DNS не прошёл проверку HTTPS");
        }
        finally{geminiGate.Release();}
    }
    private static async Task<string?> CheckGemini(string ip,CancellationToken ct)
    {
        var handler=new SocketsHttpHandler(){UseProxy=false,AllowAutoRedirect=false};
        handler.ConnectCallback=async(_,token)=>
        {
            var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
            try{await socket.ConnectAsync(IPAddress.Parse(ip),443,token);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}
        };
        using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(6)};
        try
        {
            using var request=new HttpRequestMessage(HttpMethod.Get,"https://gemini.google.com/app");request.Headers.UserAgent.ParseAdd("Mozilla/5.0");
            using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);
            return response.StatusCode==HttpStatusCode.OK?ip:null;
        }
        catch(Exception ex)when(ex is IOException or HttpRequestException or OperationCanceledException){return null;}
    }
    public void Dispose(){client.Dispose();geoClient.Dispose();}
}
