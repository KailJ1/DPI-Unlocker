using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
namespace DPIUnlocker;
internal sealed class DohResolver : IDisposable
{
    private readonly (string Name,HttpClient Client,Uri Endpoint)[] providers;
    public event Action<string>? Log;
    private int active;
    public DohResolver()
    {
        providers=new[]{("Cloudflare 1.1.1.1","cloudflare-dns.com","1.1.1.1"),("Cloudflare 1.0.0.1","cloudflare-dns.com","1.0.0.1"),("Google 8.8.8.8","dns.google","8.8.8.8")}.Select(p=>
        {
            var handler=new SocketsHttpHandler{UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(2),PooledConnectionLifetime=TimeSpan.FromMinutes(5),MaxConnectionsPerServer=8};
            handler.ConnectCallback=async(_,ct)=>
            {
                var socket=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp){NoDelay=true};
                try{await socket.ConnectAsync(IPAddress.Parse(p.Item3),443,ct);return new NetworkStream(socket,true);}catch{socket.Dispose();throw;}
            };
            var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(4)};
            return(p.Item1,client,new Uri($"https://{p.Item2}/dns-query"));
        }).ToArray();
    }
    public async Task<byte[]> Resolve(byte[] original,CancellationToken ct)
    {
        byte[] query=(byte[])original.Clone();query[0]=0;query[1]=0;
        int first=Volatile.Read(ref active);
        for(int i=0;i<providers.Length;i++)
        {
            int index=(first+i)%providers.Length;var provider=providers[index];
            try
            {
                using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);timeout.CancelAfter(TimeSpan.FromSeconds(4));
                using var request=new HttpRequestMessage(HttpMethod.Post,provider.Endpoint);
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));
                request.Content=new ByteArrayContent(query);request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/dns-message");
                using var response=await provider.Client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token);response.EnsureSuccessStatusCode();
                if(response.Content.Headers.ContentType?.MediaType!="application/dns-message")throw new IOException("Unexpected DoH media type");
                using var body=await response.Content.ReadAsStreamAsync(timeout.Token);using var bytes=new MemoryStream();
                byte[] buffer=new byte[8192];int n;
                while((n=await body.ReadAsync(buffer,timeout.Token))>0){if(bytes.Length+n>65507)throw new IOException("DoH response too large");bytes.Write(buffer,0,n);}
                byte[] answer=bytes.ToArray();if(!DnsWire.Matches(original,answer))throw new IOException("DoH question mismatch");
                answer[0]=original[0];answer[1]=original[1];
                if(Interlocked.Exchange(ref active,index)!=index)Log?.Invoke("DOH: резервный сервер "+provider.Name);
                return answer;
            }
            catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
            catch(Exception ex)when(ex is HttpRequestException or IOException or OperationCanceledException){Log?.Invoke("DOH_ENDPOINT_FAIL "+provider.Name+" "+ex.GetBaseException().Message);}
        }
        throw new IOException("Все DoH-серверы недоступны; незашифрованный DNS не использован");
    }
    public void Dispose(){foreach(var p in providers)p.Client.Dispose();}
}

