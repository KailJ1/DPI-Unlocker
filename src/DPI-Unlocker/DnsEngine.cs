using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal sealed class DnsEngine : IDisposable
{
    [DllImport("dnsapi.dll")][return:MarshalAs(UnmanagedType.Bool)]private static extern bool DnsFlushResolverCache();
    private IntPtr handle;private readonly object sendGate=new();
    private readonly ConcurrentDictionary<string,byte> pending=new();
    private readonly ConcurrentDictionary<int,Task> operations=new();
    private int next,answered,failed;public event Action<string>? Log;
    private readonly AiRoutes? ai;
    private readonly bool useDoh;
    private readonly int smartDns;
    public DnsEngine(AiRoutes? ai=null,bool useDoh=true,int smartDns=0){this.ai=ai;this.useDoh=useDoh;this.smartDns=smartDns;}
    public void Run(CancellationToken ct)
    {
        handle=Divert.WinDivertOpen("!loopback and !impostor and udp and (outbound and udp.DstPort == 53)",0,100,0);
        if(handle==new IntPtr(-1))throw new Win32Exception(Marshal.GetLastWin32Error(),"DNS WinDivertOpen");
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var registration=ct.Register(()=>Divert.WinDivertShutdown(handle,1));
        using var resolver=new DohResolver();resolver.Log+=Emit;
        using var aiResolver=new AiDnsResolver(smartDns);aiResolver.Log+=Emit;
        DnsFlushResolverCache();
        byte[] buffer=new byte[65535],address=new byte[80];
        Emit(useDoh?"DNS: прозрачный DoH включён · Cloudflare 1.1.1.1 · без изменения DNS-адаптера":"DNS: прозрачный маршрут нейросетей; остальные запросы без изменений");
        if(ai?.Enabled==true)Emit("AI_SMART_DNS: Нейросети (ChatGPT / Gemini) через Smart DNS; HTTP-прокси не настраивается; собственный DoH браузера может обойти этот модуль");
        try
        {
            while(Divert.WinDivertRecv(handle,buffer,(uint)buffer.Length,out uint count,address))
            {
                bool v6=buffer[0]>>4==6;int udp=v6?40:(buffer[0]&15)*4;
                bool valid=v6?count>=48&&buffer[6]==17:count>=28&&udp>=20&&buffer[9]==17&&(BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6))&0x3fff)==0;
                int udpLength=valid&&count>=udp+8?BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(udp+4)):0;
                if(!valid||udpLength<20||udp+udpLength>count){Send(buffer[..(int)count],address);continue;}
                byte[] query=buffer[(udp+8)..(udp+udpLength)];var question=DnsWire.Question(query);
                if(question is null||DnsWire.Private(question)||(query[2]&0xf8)!=0){Send(buffer[..(int)count],address);continue;}
                bool aiQuery=ai?.Matches(question.Name)==true;
                if(!useDoh&&!aiQuery){Send(buffer[..(int)count],address);continue;}
                byte[] original=buffer[..(int)count],meta=(byte[])address.Clone();
                string key=Convert.ToHexString(original.AsSpan(v6?8:12,v6?32:8))+Convert.ToHexString(original.AsSpan(udp,4))+Convert.ToHexString(query);
                if(pending.Count>=256){Reply(original,meta,udp,v6,DnsWire.Failure(query));continue;}
                if(!pending.TryAdd(key,0))continue;
                int id=Interlocked.Increment(ref next);
                var work=Task.Run(async()=>
                {
                    try
                    {
                        byte[] response;
                        try
                        {
                            response=aiQuery?await aiResolver.Resolve(query,stop.Token):await resolver.Resolve(query,stop.Token);
                            if(aiQuery)ai?.Observe(response);
                            if(VideoEndpoints.IsVideoHost(question.Name))
                                foreach(string ip in DnsWire.AddressAnswers(response))
                                    VideoEndpoints.Observe(question.Name,ip);
                            Interlocked.Increment(ref answered);
                        }
                        catch(OperationCanceledException)when(stop.IsCancellationRequested){return;}
                        catch(Exception ex)when(ex is IOException or HttpRequestException){Interlocked.Increment(ref failed);Emit("DNS_FAIL "+ex.Message);response=DnsWire.Failure(query);}
                        if(!stop.IsCancellationRequested)Reply(original,meta,udp,v6,response);
                        int total=Volatile.Read(ref answered)+Volatile.Read(ref failed);
                        if(total==1||total%25==0)Emit($"DNS_STATS DoH={Volatile.Read(ref answered)} failures={Volatile.Read(ref failed)}");
                    }
                    catch(Exception ex){Emit("DNS_ERROR "+ex.Message);}
                    finally{pending.TryRemove(key,out _);operations.TryRemove(id,out _);}
                });
                operations[id]=work;
                if(work.IsCompleted)operations.TryRemove(id,out _);
            }
            if(!ct.IsCancellationRequested)throw new Win32Exception(Marshal.GetLastWin32Error(),"DNS recv stopped");
        }
        finally{stop.Cancel();try{Task.WhenAll(operations.Values).GetAwaiter().GetResult();}catch(OperationCanceledException){}Dispose();DnsFlushResolverCache();}
    }
    private void Reply(byte[] original,byte[] address,int udp,bool v6,byte[] answer)
    {
        if(answer.Length==0)return;
        byte[] packet=new byte[udp+8+answer.Length];original.AsSpan(0,udp+8).CopyTo(packet);answer.CopyTo(packet,udp+8);
        int source=v6?8:12,target=v6?24:16,size=v6?16:4;
        for(int i=0;i<size;i++)(packet[source+i],packet[target+i])=(packet[target+i],packet[source+i]);
        for(int i=0;i<2;i++)(packet[udp+i],packet[udp+2+i])=(packet[udp+2+i],packet[udp+i]);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(udp+4),(ushort)(8+answer.Length));
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(v6?4:2),(ushort)(packet.Length-(v6?40:0)));
        address[10]&=0xfd;Send(packet,address);
    }
    private void Send(byte[] packet,byte[] address)
    {
        lock(sendGate)
        {
            if(handle==IntPtr.Zero||handle==new IntPtr(-1))return;
            Divert.WinDivertHelperCalcChecksums(packet,(uint)packet.Length,address,0);
            if(!Divert.WinDivertSend(handle,packet,(uint)packet.Length,out _,address))throw new Win32Exception(Marshal.GetLastWin32Error(),"DNS send");
        }
    }
    private void Emit(string s)=>Log?.Invoke(DateTime.Now.ToString("HH:mm:ss ")+s);
    public void Dispose(){lock(sendGate){if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1)){Divert.WinDivertClose(handle);handle=IntPtr.Zero;}}}
}

