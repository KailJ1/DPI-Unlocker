using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
namespace DPIUnlocker;
internal static class TelegramTest
{
    public static async Task<int> Run()
    {
        string report=Path.Combine(AppContext.BaseDirectory,"telegram-test.log");
        void Log(string s){lock(report)File.AppendAllText(report,s+Environment.NewLine);}
        using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var redirector=new TelegramRedirector(Environment.ProcessId);redirector.Log+=Log;
        var worker=Task.Run(()=>redirector.Run(cts.Token));
        try
        {
            await Task.Delay(400,cts.Token);if(worker.IsCompleted)await worker;
            using var client=new TcpClient(){NoDelay=true};await client.ConnectAsync("149.154.167.51",443,cts.Token);
            var stream=client.GetStream();byte[] nonce=RandomNumberGenerator.GetBytes(16),body=new byte[40];
            long ms=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();ulong id=((ulong)(ms/1000)<<32)|((ulong)(ms%1000)*0x100000000UL/1000);
            BinaryPrimitives.WriteUInt64LittleEndian(body.AsSpan(8),id&~3UL);BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(16),20);
            BinaryPrimitives.WriteUInt32LittleEndian(body.AsSpan(20),0xbe7e8ef1);nonce.CopyTo(body,24);
            byte[] frame=new byte[42];frame[0]=0xef;frame[1]=10;body.CopyTo(frame,2);await stream.WriteAsync(frame,cts.Token);
            byte[] length=new byte[4];await stream.ReadExactlyAsync(length.AsMemory(0,1),cts.Token);
            int words=length[0];if(words==0x7f){await stream.ReadExactlyAsync(length.AsMemory(0,3),cts.Token);words=length[0]|length[1]<<8|length[2]<<16;}
            if(words<10||words>250000)throw new IOException("Unexpected MTProto frame length "+words);
            byte[] response=new byte[words*4];await stream.ReadExactlyAsync(response,cts.Token);
            if(BinaryPrimitives.ReadUInt32LittleEndian(response.AsSpan(20))!=0x05162463||!response.AsSpan(24,16).SequenceEqual(nonce))throw new IOException("MTProto response/nonce mismatch");
            Log("PASS: transparent TCP redirect -> WSS -> MTProto resPQ with matching nonce; no Telegram account used");return 0;
        }
        catch(Exception ex){Log("FAIL "+ex);return 1;}
        finally{cts.Cancel();try{await worker;}catch(Exception ex){Log("REDIRECTOR "+ex.Message);}}
    }
}

