using System.Buffers.Binary;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
namespace DPIUnlocker;
internal static class TelegramTransport
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<int,string> preferred=new();
    public static int DcForIp(string ip)
    {
        if(ip is "149.154.167.91" or "149.154.167.92" or "149.154.167.220")return 4;
        if(ip.StartsWith("91.105.192."))return 2;
        if(ip.StartsWith("149.154.171.")||ip.StartsWith("91.108.56."))return 5;
        if(ip.StartsWith("149.154.175."))return int.Parse(ip.Split('.')[3])>=100?3:1;
        if(ip.StartsWith("149.154.167."))return int.Parse(ip.Split('.')[3])>=200?4:2;
        if(ip.StartsWith("91.108.4."))return 4;
        if(ip.StartsWith("91.108.8."))return 2;
        if(ip.StartsWith("91.108.12."))return 3;
        return 2;
    }
    public static (byte[] Init,AesCounter Tx,AesCounter Rx) CreateInit(uint protocol,int dc)
    {
        byte[] init;
        do{init=RandomNumberGenerator.GetBytes(64);}while(init[0] is 0xef or 0x16 || BinaryPrimitives.ReadUInt32LittleEndian(init)==0 || BinaryPrimitives.ReadUInt32LittleEndian(init.AsSpan(4))==0);
        BinaryPrimitives.WriteUInt32LittleEndian(init.AsSpan(56),protocol);BinaryPrimitives.WriteInt16LittleEndian(init.AsSpan(60),(short)dc);
        byte[] reversed=init.Reverse().ToArray();
        var tx=new AesCounter(init[8..40],init[40..56]);var rx=new AesCounter(reversed[8..40],reversed[40..56]);
        byte[] encrypted=tx.Transform(init);encrypted.AsSpan(56,8).CopyTo(init.AsSpan(56));return(init,tx,rx);
    }
    public static bool IsObfuscated(byte[] init,out int dc)
        =>IsObfuscated(init,out dc,out _);
    public static bool IsObfuscated(byte[] init,out int dc,out uint protocol)
    {
        dc=0;protocol=0;if(init.Length<64)return false;
        using var cipher=new AesCounter(init[8..40],init[40..56]);var decoded=cipher.Transform(init.AsSpan(0,64));
        uint tag=BinaryPrimitives.ReadUInt32LittleEndian(decoded.AsSpan(56));
        if(tag is not (0xefefefef or 0xeeeeeeee or 0xdddddddd))return false;
        protocol=tag;
        int number=Math.Abs((int)BinaryPrimitives.ReadInt16LittleEndian(decoded.AsSpan(60)));if(number is >=1 and <=5)dc=number;return true;
    }
    public static async Task<ClientWebSocket> Connect(int dc,CancellationToken ct,Action<string>? log=null)
    {
        var relays=await TelegramRelayPool.Get(ct);
        var candidates=relays.Select(domain=>$"kws{dc}.{domain}").Concat(new[]{$"kws{dc}.web.telegram.org",$"kws{dc}-1.web.telegram.org"}).ToList();
        if(preferred.TryGetValue(dc,out var previous)){candidates.Remove(previous);candidates.Insert(0,previous);}
        async Task<(string Host,ClientWebSocket? Socket)> Try(string host,CancellationToken token)
        {
            var ws=new ClientWebSocket();ws.Options.Proxy=null;ws.Options.AddSubProtocol("binary");ws.Options.KeepAliveInterval=Timeout.InfiniteTimeSpan;
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(token);timeout.CancelAfter(TimeSpan.FromSeconds(4));
            try{await ws.ConnectAsync(new Uri($"wss://{host}/apiws"),timeout.Token);return(host,ws);}
            catch(Exception ex)when(ex is WebSocketException or OperationCanceledException or HttpRequestException){ws.Dispose();return(host,null);}
        }
        foreach(var group in candidates.Chunk(3))
        {
            ct.ThrowIfCancellationRequested();using var race=CancellationTokenSource.CreateLinkedTokenSource(ct);
            var tasks=group.Select(host=>Try(host,race.Token)).ToList();var remaining=tasks.ToList();
            ClientWebSocket? winner=null;
            while(remaining.Count>0)
            {
                var finished=await Task.WhenAny(remaining);remaining.Remove(finished);var result=await finished;
                if(result.Socket is null)continue;winner=result.Socket;preferred[dc]=result.Host;race.Cancel();break;
            }
            foreach(var result in await Task.WhenAll(tasks))if(result.Socket is not null&&result.Socket!=winner)result.Socket.Dispose();
            if(winner is not null){log?.Invoke($"TELEGRAM_UPSTREAM DC{dc} host={preferred[dc]}");return winner;}
        }
        throw new IOException($"Telegram DC{dc}: прямые и CF WebSocket-маршруты недоступны");
    }
    public static async Task Bridge(TcpClient client,string destination,Action<string> log,CancellationToken ct,int port=443)
    {
        using(client)
        using(var linked=CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            var lifetime=System.Diagnostics.Stopwatch.StartNew();long uploaded=0,downloaded=0;
            string connection=Guid.NewGuid().ToString("N")[..8];
            void Trace(string message)=>log($"{message} conn={connection}");
            try
            {
            var stream=client.GetStream();byte[] prefix=new byte[64];
            using(var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                timeout.CancelAfter(TimeSpan.FromSeconds(8));await stream.ReadExactlyAsync(prefix.AsMemory(0,1),timeout.Token);
                int count=prefix[0]==0xef?1:4;
                if(count>1)await stream.ReadExactlyAsync(prefix.AsMemory(1,3),timeout.Token);
                if(prefix.AsSpan(0,4).SequenceEqual("POST"u8))
                {
                    await TelegramHttpTransport.Bridge(stream,prefix[..4],DcForIp(destination),Trace,linked.Token);return;
                }
                uint marker=count==1?0xefefefefu:BinaryPrimitives.ReadUInt32LittleEndian(prefix);
                bool plain=marker is 0xefefefef or 0xeeeeeeee or 0xdddddddd;
                int dc=DcForIp(destination);AesCounter? clientDecoder=null,clientEncoder=null;
                if(!plain)
                {
                    await stream.ReadExactlyAsync(prefix.AsMemory(4,60),timeout.Token);
                    if(!IsObfuscated(prefix,out int headerDc,out marker))
                    {
                        log("TELEGRAM_DIRECT unknown transport; preserving original stream");
                        using var direct=new TcpClient(){NoDelay=true};
                        string connectDst=destination is "149.154.167.99" or "149.154.165.133" or "149.154.165.137" or "149.154.164.24" or "149.154.164.25" or "149.154.175.204" or "149.154.175.205" or "149.154.171.236" or "149.154.171.237"?"149.154.167.220":destination;
                        await direct.ConnectAsync(connectDst,port,timeout.Token);
                        using var upstream=direct.GetStream();await upstream.WriteAsync(prefix,ct);
                        var upload=stream.CopyToAsync(upstream,linked.Token);var download=upstream.CopyToAsync(stream,linked.Token);
                        await Task.WhenAny(upload,download);linked.Cancel();
                        try{await Task.WhenAll(upload,download);}catch(OperationCanceledException){}return;
                    }
                    if(headerDc!=0)dc=headerDc;
                    clientDecoder=new AesCounter(prefix[8..40],prefix[40..56]);clientDecoder.Transform(new byte[64]);
                    byte[] reversed=prefix.Reverse().ToArray();clientEncoder=new AesCounter(reversed[8..40],reversed[40..56]);
                }
                using var ws=await Connect(dc,ct,Trace);
                var created=CreateInit(marker,dc);prefix=created.Init;
                using var tx=created.Tx;using var rx=created.Rx;
                using(clientDecoder)using(clientEncoder)
                {
                    await ws.SendAsync(prefix,WebSocketMessageType.Binary,true,linked.Token);
                    Trace($"TELEGRAM_WS DC{dc} connected transport={marker:x8} (содержимое сообщений не расшифровывается)");
                    async Task Up()
                    {
                        byte[] buffer=new byte[65536];int n;var pending=new List<byte>();
                        while((n=await stream.ReadAsync(buffer,linked.Token))>0)
                        {
                            byte[] data=clientDecoder is null?buffer.AsSpan(0,n).ToArray():clientDecoder.Transform(buffer.AsSpan(0,n));
                            pending.AddRange(data);
                            while(pending.Count>0)
                            {
                                int header=marker==0xefefefef?((pending[0]&127)==127?4:1):4;
                                if(pending.Count<header)break;
                                int payload=marker==0xefefefef?(header==1?(pending[0]&127)*4:(pending[1]|pending[2]<<8|pending[3]<<16)*4):(int)(BinaryPrimitives.ReadUInt32LittleEndian(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(pending))&0x7fffffff);
                                if(payload<=0||payload>16*1024*1024)throw new IOException("Некорректный размер MTProto transport frame");
                                int length=header+payload;if(pending.Count<length)break;
                                byte[] encrypted=tx.Transform(System.Runtime.InteropServices.CollectionsMarshal.AsSpan(pending)[..length]);pending.RemoveRange(0,length);
                                await ws.SendAsync(encrypted,WebSocketMessageType.Binary,true,linked.Token);
                                Interlocked.Add(ref uploaded,length);
                            }
                        }
                    }
                    async Task Down()
                    {
                        byte[] buffer=new byte[65536];
                        while(ws.State==WebSocketState.Open)
                        {
                            var read=await ws.ReceiveAsync(buffer.AsMemory(),linked.Token);
                            if(read.MessageType==WebSocketMessageType.Close)break;
                            if(read.MessageType!=WebSocketMessageType.Binary)continue;
                            byte[] data=rx.Transform(buffer.AsSpan(0,read.Count));
                            if(clientEncoder is not null)data=clientEncoder.Transform(data);
                            await stream.WriteAsync(data,linked.Token);
                            Interlocked.Add(ref downloaded,data.Length);
                        }
                    }
                    var up=Up();var down=Down();await Task.WhenAny(up,down);linked.Cancel();ws.Abort();
                    try{await Task.WhenAll(up,down);}catch(OperationCanceledException){}
                }
            }
            }
            finally{linked.Cancel();Trace($"TELEGRAM_END destination={destination}:{port} seconds={lifetime.Elapsed.TotalSeconds:F1} up={uploaded} down={downloaded} serviceStop={ct.IsCancellationRequested}");}
        }
    }
}

