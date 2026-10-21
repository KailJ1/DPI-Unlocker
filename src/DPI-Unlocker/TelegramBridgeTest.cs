using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
namespace DPIUnlocker;
internal static class TelegramBridgeTest
{
    public static async Task<int> Run(bool sustained=false)
    {
        string report=Path.Combine(AppContext.BaseDirectory,"telegram-bridge-test.txt");
        var lines=new List<string>();
        try
        {
            foreach(bool http in new[]{false,true})
            {
                using var ct=new CancellationTokenSource(TimeSpan.FromSeconds(sustained?110:40));
                using var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
                using var client=new TcpClient(){NoDelay=true};
                await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint,ct.Token);
                using var accepted=await listener.AcceptTcpClientAsync(ct.Token);
                Task bridge=TelegramTransport.Bridge(accepted,"149.154.167.41",s=>{lock(lines)lines.Add(s);},ct.Token,80);
                try
                {
                    for(int iteration=0;iteration<(sustained?7:2);iteration++)
                    {
                        if(sustained&&iteration>0)await Task.Delay(TimeSpan.FromSeconds(12),ct.Token);
                        byte[] nonce=RandomNumberGenerator.GetBytes(16),body=new byte[40];
                        ulong id=(ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()<<32;
                        BinaryPrimitives.WriteUInt64LittleEndian(body.AsSpan(8),id+(uint)(iteration*4));
                        BinaryPrimitives.WriteInt32LittleEndian(body.AsSpan(16),20);
                        BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(20),0xbe7e8ef1);nonce.CopyTo(body,24);
                        var stream=client.GetStream();
                        if(http)
                        {
                            await stream.WriteAsync(Encoding.ASCII.GetBytes("POST /api HTTP/1.1\r\nHost: 149.154.167.41\r\nContent-Length: 40\r\nConnection: keep-alive\r\n\r\n"),ct.Token);
                        }
                        else await stream.WriteAsync(iteration==0?new byte[]{0xef,10}:new byte[]{10},ct.Token);
                        await stream.WriteAsync(body,ct.Token);
                        int size;
                        if(http)
                        {
                            var header=new List<byte>();var one=new byte[1];
                            while(header.Count<4||!header.TakeLast(4).SequenceEqual(new byte[]{13,10,13,10}))
                            {await stream.ReadExactlyAsync(one,ct.Token);header.Add(one[0]);if(header.Count>16384)throw new IOException("Large HTTP header");}
                            string text=Encoding.ASCII.GetString(header.ToArray());
                            if(!text.StartsWith("HTTP/1.1 200"))throw new IOException(text);
                            size=int.Parse(text.Split("\r\n").Single(s=>s.StartsWith("Content-Length:")).Split(':')[1]);
                        }
                        else
                        {
                            byte[] length=new byte[3];await stream.ReadExactlyAsync(length.AsMemory(0,1),ct.Token);size=length[0]*4;
                            if(length[0]==127){await stream.ReadExactlyAsync(length,ct.Token);size=(length[0]|length[1]<<8|length[2]<<16)*4;}
                        }
                        if(size<40||size>1000000)throw new IOException("Invalid response size");
                        byte[] response=new byte[size];await stream.ReadExactlyAsync(response,ct.Token);
                        if(BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(20))!=0x05162463||!response.AsSpan(24,16).SequenceEqual(nonce))throw new IOException("MTProto resPQ nonce mismatch");
                        lines.Add($"PASS {(http?"HTTP POST":"abridged TCP")} request {iteration+1}: resPQ nonce verified");
                    }
                }
                finally{ct.Cancel();client.Dispose();try{await bridge;}catch(OperationCanceledException){}catch(IOException)when(ct.IsCancellationRequested){}}
            }
            File.WriteAllLines(report,lines);return 0;
        }
        catch(Exception ex){lines.Add("FAIL "+ex);File.WriteAllLines(report,lines);return 1;}
    }
}

