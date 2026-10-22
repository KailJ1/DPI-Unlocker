using System.Net.Http.Headers;
namespace DPIUnlocker;

// Only DNS uses this client. The browser retains its original hostname and TLS session.
internal sealed class AiDnsResolver:IDisposable
{
    internal static readonly string[] Endpoints=["https://dns.zapret.moe/dns-query","https://dns.comss.one/dns-query"];
    private readonly HttpClient client=new(new SocketsHttpHandler(){UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(3),PooledConnectionLifetime=TimeSpan.FromMinutes(5),MaxConnectionsPerServer=8}){Timeout=TimeSpan.FromSeconds(8)};
    private readonly int selection;
    private int active;
    internal AiDnsResolver(int provider=0){selection=provider;active=provider==2?1:0;}
    internal event Action<string>? Log;
    internal async Task<byte[]> Resolve(byte[] original,CancellationToken ct)
    {
        int first=Volatile.Read(ref active);
        for(int attempt=0;attempt<(selection==0?Endpoints.Length:1);attempt++)
        {
            int index=(first+attempt)%Endpoints.Length;
            try
            {
                using var request=new HttpRequestMessage(HttpMethod.Post,Endpoints[index]);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                request.Content=new ByteArrayContent(original);request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/dns-message");
                using var response=await client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);response.EnsureSuccessStatusCode();
                if(response.Content.Headers.ContentType?.MediaType!="application/dns-message")throw new IOException("Unexpected Smart DNS media type");
                using var body=await response.Content.ReadAsStreamAsync(ct);using var output=new MemoryStream();
                byte[] buffer=new byte[8192];int read;
                while((read=await body.ReadAsync(buffer,ct))!=0){if(output.Length+read>65507)throw new IOException("Smart DNS response too large");output.Write(buffer,0,read);}
                byte[] answer=output.ToArray();if(!DnsWire.Matches(original,answer)||(answer[3]&15)!=0)throw new IOException("Smart DNS question or response mismatch");
                answer[0]=original[0];answer[1]=original[1];
                Interlocked.Exchange(ref active,index);
                Log?.Invoke("AI_DNS "+DnsWire.Question(original)!.Name+" provider="+new Uri(Endpoints[index]).Host);
                return answer;
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
            catch(Exception ex)when(ex is IOException or HttpRequestException or OperationCanceledException)
            {Log?.Invoke("AI_DNS_ENDPOINT_FAIL "+new Uri(Endpoints[index]).Host+" "+ex.GetBaseException().Message);}
        }
        throw new IOException("Smart DNS недоступен. Переключите сервер Smart DNS или снимите галочку сервиса.");
    }
    public void Dispose()=>client.Dispose();
}
