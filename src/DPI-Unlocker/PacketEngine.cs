using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal static class Divert
{
    [DllImport("WinDivert.dll", EntryPoint="WinDivertOpen", CharSet=CharSet.Ansi, SetLastError=true)] private static extern IntPtr OpenNative(string filter,int layer,short priority,ulong flags);
    private static readonly object openGate=new();
    public static IntPtr WinDivertOpen(string filter,int layer,short priority,ulong flags)
    {
        lock(openGate)
        {
            IntPtr result=IntPtr.Zero;int error=0;
            for(int attempt=0;attempt<4;attempt++)
            {
                result=OpenNative(filter,layer,priority,flags);error=Marshal.GetLastWin32Error();
                if(result!=new IntPtr(-1)||!RetryableOpenError(error))break;
                if(attempt<3)Thread.Sleep(250);
            }
            if(result==new IntPtr(-1)&&error==1058)
                throw new Win32Exception(error,"WinDivert: Windows запретила запуск необходимой службы (1058). Проверьте WinDivert и BFE.\n"+DriverPrerequisites.Report(false));
            Marshal.SetLastPInvokeError(error);return result;
        }
    }
    internal static bool RetryableOpenError(int error)=>unchecked((uint)error) is 0x80320009 or 0x8032000a;
    [DllImport("WinDivert.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WinDivertRecv(IntPtr h,byte[] packet,uint size,out uint read,byte[] address);
    [DllImport("WinDivert.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WinDivertSend(IntPtr h,byte[] packet,uint size,out uint sent,byte[] address);
    [DllImport("WinDivert.dll")] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WinDivertHelperCalcChecksums(byte[] packet,uint size,byte[] address,ulong flags);
    [DllImport("WinDivert.dll")] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WinDivertShutdown(IntPtr h,int how);
    [DllImport("WinDivert.dll")] [return:MarshalAs(UnmanagedType.Bool)] public static extern bool WinDivertClose(IntPtr h);
}
internal sealed class PacketEngine : IDisposable
{
    private IntPtr handle;
    private readonly Dictionary<string,FlowState> flows=new();
    private readonly Dictionary<string,int> learned=new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string,(int Mode,DateTime Until)> resetRetries=new(StringComparer.OrdinalIgnoreCase);
    internal static string StrategyKey(string host,string destination)=>host+"|"+destination;
    private readonly ClientHelloTracker hellos=new();
    private readonly int forced;
    private readonly Func<PacketInfo,int>? strategySelector;
    private long received,changed,confirmed;
    public event Action<string>? Log;
    private sealed class FlowState { public uint Sequence; public int Mode; public string Host="",Destination=""; public DateTime Seen; public bool Responded; public string Key=>StrategyKey(Host,Destination); }
    private readonly AiRoutes? ai;
    public PacketEngine(int mode=-1,Func<PacketInfo,int>? strategySelector=null,AiRoutes? ai=null) { forced=mode;this.strategySelector=strategySelector;this.ai=ai; }
    private static int NextMode(int mode)=>mode switch{7=>8,8=>3,3=>0,0=>1,1=>6,6=>5,5=>2,2=>4,_=>7};
    private static bool IsAnycastOrEdge(string host,string ip)=>
        host.EndsWith("cloudflare.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("cloudflareinsights.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("pages.dev",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("workers.dev",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("cloudflareclient.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("cdnjs.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("trycloudflare.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("chatgpt.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("openai.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("oaistatic.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("oaiusercontent.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("aeza.ru",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("aeza.net",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("edgecenter.ru",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("gcore.com",StringComparison.OrdinalIgnoreCase)||
        host.EndsWith("gcorelabs.com",StringComparison.OrdinalIgnoreCase)||
        ip.StartsWith("95.181.176.")||ip.StartsWith("95.181.177.")||ip.StartsWith("95.181.178.")||ip.StartsWith("95.181.179.")||
        ip.StartsWith("92.223.")||ip.StartsWith("92.38.")||
        ip.StartsWith("104.16.")||ip.StartsWith("104.17.")||ip.StartsWith("104.18.")||ip.StartsWith("104.19.")||
        ip.StartsWith("104.20.")||ip.StartsWith("104.21.")||ip.StartsWith("104.22.")||ip.StartsWith("104.23.")||
        ip.StartsWith("104.24.")||ip.StartsWith("104.25.")||ip.StartsWith("104.26.")||ip.StartsWith("104.27.")||
        ip.StartsWith("172.64.")||ip.StartsWith("172.65.")||ip.StartsWith("172.66.")||ip.StartsWith("172.67.")||
        ip.StartsWith("172.68.")||ip.StartsWith("172.69.")||ip.StartsWith("172.70.")||ip.StartsWith("172.71.")||
        ip.StartsWith("162.158.")||ip.StartsWith("162.159.")||ip.StartsWith("108.162.")||ip.StartsWith("198.41.")||
        ip.StartsWith("173.245.")||ip.StartsWith("188.114.")||ip.StartsWith("190.93.")||ip.StartsWith("141.101.");
    public void Run(CancellationToken ct)
    {
        using var single=new Mutex(false,"Global\\Unlocker.PacketEngine.v1");
        bool owns;
        try { owns=single.WaitOne(0); } catch(AbandonedMutexException){owns=true;}
        if(!owns)throw new InvalidOperationException("Другой экземпляр движка DPI-Unlocker уже запущен.");
        try { RunCore(ct); } finally {single.ReleaseMutex();}
    }
    private void RunCore(CancellationToken ct)
    {
        // Only TLS handshake replies and resets need inspection. Diverting every
        // downloaded video packet through this single-threaded loop unnecessarily queues bulk data.
        const string filter="!loopback and !impostor and tcp and ((outbound and (tcp.DstPort == 443 or tcp.DstPort == 80 or tcp.DstPort == 8443 or tcp.DstPort == 2053 or tcp.DstPort == 2083 or tcp.DstPort == 2087 or tcp.DstPort == 2096) and tcp.PayloadLength > 0) or (inbound and (tcp.SrcPort == 443 or tcp.SrcPort == 80 or tcp.SrcPort == 8443 or tcp.SrcPort == 2053 or tcp.SrcPort == 2083 or tcp.SrcPort == 2087 or tcp.SrcPort == 2096) and ((tcp.PayloadLength > 0 and tcp.Payload[0] == 22) or tcp.Rst)))";
        handle=Divert.WinDivertOpen(filter,0,0,0);
        if(handle==new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(),"WinDivertOpen: нужны права администратора; проверьте доступность драйвера");
        using var reg=ct.Register(()=>Divert.WinDivertShutdown(handle,1));
        byte[] packet=new byte[65535],addr=new byte[80];
        Emit($"RUNNING mode={forced} PID={Environment.ProcessId}");
        DateTime report=DateTime.UtcNow;
        try
        {
            while(Divert.WinDivertRecv(handle,packet,(uint)packet.Length,out uint count,addr))
            {
                received++; bool sent=false;
                try
                {
                    var p=Packets.Parse(packet,(int)count);
                    bool outbound=(addr[10]&2)!=0;
                    if(p is not null && !outbound)
                    {
                        string reverse=Packets.ReverseFlow(packet,p);
                        if((packet[p.Tcp+13]&4)!=0 && flows.TryGetValue(reverse,out var failed))
                        {
                            // A reset terminates this flow. Give its replacement a
                            // short-lived retry hint, separate from confirmed successes.
                            if(forced<0&&!failed.Responded)
                            {
                                if(learned.TryGetValue(failed.Key,out int cached)&&cached==failed.Mode)learned.Remove(failed.Key);
                                resetRetries[failed.Key]=(VideoEndpoints.IsVideoHost(failed.Host)?(failed.Mode==7?8:7):NextMode(failed.Mode),DateTime.UtcNow.AddSeconds(15));
                            }
                            Emit($"CONNECTION_RESET {failed.Host} strategy={failed.Mode} tlsReplySeen={failed.Responded}");
                        }
                        if(flows.TryGetValue(reverse,out var state) && !state.Responded && p.End>p.Payload && packet[p.Payload]==22)
                        {
                            state.Responded=true; learned[state.Key]=state.Mode; confirmed++;
                            resetRetries.Remove(state.Key);
                            Emit($"TLS_REPLY {state.Host} strategy={state.Mode} (ответ TLS получен; загрузка страницы проверяется отдельно)");
                        }
                    }
                    if(p is not null && outbound && p.End>p.Payload)
                    {
                        var data=packet.AsSpan(p.Payload,p.End-p.Payload);
                        var tracked=forced==4?default:hellos.Observe(p.Flow,p.Seq,data);
                        if(tracked.Continuation)
                        {
                            if(tracked.Host is not null&&flows.TryGetValue(p.Flow,out var initial))
                            {
                                bool discovered=!initial.Host.Equals(tracked.Host,StringComparison.OrdinalIgnoreCase);
                                initial.Host=tracked.Host;
                                VideoEndpoints.Observe(tracked.Host,p.Destination);
                                if(discovered&&forced<0&&strategySelector is null)
                                    initial.Mode=learned.GetValueOrDefault(initial.Key,VideoEndpoints.IsVideoHost(initial.Host)?7:initial.Mode);
                                Emit($"HELLO_SNI {tracked.Host} ip={p.Destination} strategy={initial.Mode} (streamed, no buffering delay)");
                            }
                            // Never overlap the preceding, already-sent TLS bytes.
                            int continuationMode=flows.TryGetValue(p.Flow,out var continuing)&&continuing.Mode is 7 or 8?continuing.Mode:0;
                            foreach(var part in Packets.Transform(packet,p,continuationMode,tracked.Split))Send(part,addr);
                            sent=true;changed++;
                        }
                        bool hello=data.Length>5&&data[0]==22 && data[1]==3 && data[5]==1;
                        bool http=data.StartsWith("GET "u8)||data.StartsWith("POST "u8)||data.StartsWith("HEAD "u8);
                        if(hello||http)
                        {
                            var sni=TlsFragmenter.FindSni(data);
                            string host=sni.Offset>0?System.Text.Encoding.ASCII.GetString(data.Slice(sni.Offset,sni.Length)):p.Destination;
                            VideoEndpoints.Observe(host,p.Destination);
                            if(!flows.TryGetValue(p.Flow,out var state)||state.Sequence!=p.Seq)
                            {
                                // Learn successful strategies per destination: different addresses
                                // of one CDN hostname can take different network paths.
                                bool isTelegramWeb=host.EndsWith("telegram.org",StringComparison.OrdinalIgnoreCase)||host.EndsWith("telegra.ph",StringComparison.OrdinalIgnoreCase)||host.EndsWith("telesco.pe",StringComparison.OrdinalIgnoreCase)||host is "149.154.167.220" or "149.154.167.99" or "149.154.164.13" or "149.154.165.133" or "149.154.165.137" or "149.154.164.24" or "149.154.164.25" or "149.154.175.204" or "149.154.175.205" or "149.154.171.236" or "149.154.171.237";
                                bool video=VideoEndpoints.IsVideoHost(host)||(host==p.Destination&&VideoEndpoints.IsVideoEndpoint(p.Destination));
                                bool isAi=(ai?.IsEndpoint(p.Destination)==true)||(ai?.Matches(host)==true);
                                int initialMode=isTelegramWeb?3:(video?7:(isAi?3:(IsAnycastOrEdge(host,p.Destination)?5:3)));
                                string key=StrategyKey(host,p.Destination);
                                int fallback=resetRetries.TryGetValue(key,out var retry)&&retry.Until>DateTime.UtcNow?retry.Mode:initialMode;
                                int defaultMode=forced>=0?forced:learned.GetValueOrDefault(key,fallback);
                                state=new(){Sequence=p.Seq,Mode=strategySelector?.Invoke(p)??defaultMode,Host=host,Destination=p.Destination,Seen=DateTime.UtcNow};
                                flows[p.Flow]=state;
                                Emit($"HELLO {host} ip={p.Destination} bytes={data.Length} sniOffset={sni.Offset} strategy={state.Mode}");
                            }
                            else if(forced<0 && !state.Responded && DateTime.UtcNow-state.Seen>TimeSpan.FromMilliseconds(500))
                            {
                                if(learned.TryGetValue(state.Key,out int cached)&&cached==state.Mode)learned.Remove(state.Key);
                                state.Mode = VideoEndpoints.IsVideoHost(state.Host) ? (state.Mode == 7 ? 8 : 7) : NextMode(state.Mode);
                                state.Seen=DateTime.UtcNow;
                                Emit($"RETRY {host} strategy={state.Mode}");
                            }
                            // Keep-alive HTTP requests must not overlap acknowledged data.
                            var parts=Packets.Transform(packet,p,http&&forced<0?0:state.Mode);
                            foreach(var part in parts) Send(part,addr);
                            sent=true; changed++;
                        }
                    }
                }
                catch(Exception ex) { Emit("PACKET_ERROR "+ex.Message); }
                if(!sent) Send(packet.AsSpan(0,(int)count).ToArray(),addr);
                if(DateTime.UtcNow-report>TimeSpan.FromSeconds(2))
                {
                    report=DateTime.UtcNow;
                    Emit($"STATS received={received} changed={changed} tlsReplies={confirmed}");
                    foreach(var key in flows.Where(x=>DateTime.UtcNow-x.Value.Seen>TimeSpan.FromMinutes(2)).Select(x=>x.Key).ToArray()) flows.Remove(key);
                    if(learned.Count>4096) learned.Clear();
                    foreach(var key in resetRetries.Where(x=>x.Value.Until<DateTime.UtcNow).Select(x=>x.Key).ToArray())resetRetries.Remove(key);
                    hellos.Trim();
                }
            }
            int error=Marshal.GetLastWin32Error();
            if(!ct.IsCancellationRequested) throw new Win32Exception(error,"WinDivertRecv stopped");
        }
        finally { Dispose();Emit("STOPPED"); }
    }
    private void Send(byte[] p,byte[] addr)
    {
        if(!Divert.WinDivertHelperCalcChecksums(p,(uint)p.Length,addr,0)) throw new IOException("Checksum calculation failed");
        if(!Divert.WinDivertSend(handle,p,(uint)p.Length,out uint sent,addr)||sent!=p.Length) throw new Win32Exception(Marshal.GetLastWin32Error(),"WinDivertSend");
    }
    private void Emit(string s)=>Log?.Invoke(DateTime.Now.ToString("HH:mm:ss ")+s);
    public void Dispose() { if(handle!=IntPtr.Zero && handle!=new IntPtr(-1)) { Divert.WinDivertClose(handle); handle=IntPtr.Zero; } }
}

