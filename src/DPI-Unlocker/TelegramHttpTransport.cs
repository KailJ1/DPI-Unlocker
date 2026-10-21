using System.Buffers.Binary;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
namespace DPIUnlocker;
internal static class TelegramHttpTransport
{
    public static async Task Bridge(NetworkStream stream,byte[] prefix,int dc,Action<string> log,CancellationToken ct)
    {
        using var ws=await TelegramTransport.Connect(dc,ct,log);var init=TelegramTransport.CreateInit(0xeeeeeeee,dc);
        using var tx=init.Tx;using var rx=init.Rx;
        await ws.SendAsync(init.Init,WebSocketMessageType.Binary,true,ct);
        log($"TELEGRAM_HTTP DC{dc} connected via WebSocket");
        var received=new List<byte>();
        async Task<byte[]> ReadFrame()
        {
            var buffer=new byte[65536];
            while(true)
            {
                if(received.Count>=4)
                {
                    int size=BinaryPrimitives.ReadInt32LittleEndian(CollectionsMarshal.AsSpan(received));
                    if(size<0||size>16*1024*1024)throw new IOException("Invalid Telegram HTTP response size");
                    if(received.Count>=4+size){byte[] body=received.GetRange(4,size).ToArray();received.RemoveRange(0,4+size);return body;}
                }
                var result=await ws.ReceiveAsync(buffer.AsMemory(),ct);
                if(result.MessageType==WebSocketMessageType.Close)throw new IOException("Telegram HTTP upstream closed");
                if(result.MessageType==WebSocketMessageType.Binary)received.AddRange(rx.Transform(buffer.AsSpan(0,result.Count)));
            }
        }
        while(true)
        {
            var header=new List<byte>(prefix);var one=new byte[1];
            while(header.Count<4||!header.TakeLast(4).SequenceEqual(new byte[]{13,10,13,10}))
            {
                if(header.Count>=16384)throw new IOException("Telegram HTTP headers too large");
                if(await stream.ReadAsync(one,ct)==0)return;header.Add(one[0]);
            }
            string text=Encoding.ASCII.GetString(header.ToArray());
            string? length=text.Split("\r\n").FirstOrDefault(s=>s.StartsWith("Content-Length:",StringComparison.OrdinalIgnoreCase));
            if(!text.StartsWith("POST ",StringComparison.Ordinal)||length is null||!int.TryParse(length.Split(':',2)[1].Trim(),out int size)||size<0||size>16*1024*1024)
                throw new IOException("Unsupported Telegram HTTP request framing");
            byte[] frame=new byte[size+4];BinaryPrimitives.WriteInt32LittleEndian(frame,size);
            await stream.ReadExactlyAsync(frame.AsMemory(4),ct);
            await ws.SendAsync(tx.Transform(frame),WebSocketMessageType.Binary,true,ct);
            byte[] response=await ReadFrame();
            byte[] responseHeader=Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {response.Length}\r\nConnection: keep-alive\r\n\r\n");
            await stream.WriteAsync(responseHeader,ct);await stream.WriteAsync(response,ct);prefix=[];
        }
    }
}

