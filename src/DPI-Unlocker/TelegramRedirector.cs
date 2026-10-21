using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal sealed class TelegramRedirector : IDisposable
{
    private const int Port=18243;
    private IntPtr handle;
    private readonly TcpListener listener=new(IPAddress.Any,Port);
    private readonly ConcurrentDictionary<string,Mapping> mappings=new();
    private readonly ConcurrentDictionary<int,TcpClient> clients=new();
    private readonly int testPid;
    private int nextClient;
    private int testClaimed;
    private sealed record Mapping(string Destination,ushort Port,DateTime Seen,int ProcessId);
    public event Action<string>? Log;
    public TelegramRedirector(int testProcess=0){testPid=testProcess;}
    public void Run(CancellationToken ct)
    {
        using var firewall=new TelegramFirewall();
        listener.Start(128);
        const string ranges="(ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255) or (ip.DstAddr >= 91.108.0.0 and ip.DstAddr <= 91.108.255.255) or (ip.DstAddr >= 91.105.192.0 and ip.DstAddr <= 91.105.192.255)";
        const string excludeIps="ip.DstAddr != 149.154.167.99 and ip.DstAddr != 149.154.167.220 and ip.DstAddr != 149.154.164.13 and ip.DstAddr != 149.154.165.133 and ip.DstAddr != 149.154.165.137 and ip.DstAddr != 149.154.164.24 and ip.DstAddr != 149.154.164.25 and ip.DstAddr != 149.154.175.204 and ip.DstAddr != 149.154.175.205 and ip.DstAddr != 149.154.171.236 and ip.DstAddr != 149.154.171.237";
        string filter=$"outbound and !loopback and !impostor and ip and tcp and (tcp.SrcPort == {Port} or (({ranges}) and ({excludeIps}) and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 5222)))";
        handle=Divert.WinDivertOpen(filter,0,50,0);
        if(handle==new IntPtr(-1)){listener.Stop();throw new Win32Exception(Marshal.GetLastWin32Error(),"Telegram redirect WinDivertOpen");}
        using var cancel=ct.Register(()=>{Divert.WinDivertShutdown(handle,1);listener.Stop();foreach(var client in clients.Values)client.Dispose();});
        var accept=Accept(ct);
        byte[] packet=new byte[65535],address=new byte[80];
        Emit("TELEGRAM: прозрачный IPv4-перехват включён, настройки Telegram не меняются");
        try
        {
            while(Divert.WinDivertRecv(handle,packet,(uint)packet.Length,out uint count,address))
            {
                try
                {
                    var p=Packets.Parse(packet,(int)count);
                    if(p is not null&&!p.V6)
                    {
                        ushort sourcePort=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(p.Tcp));
                        ushort targetPort=BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(p.Tcp+2));
                        if(sourcePort==Port)
                        {
                            string key=p.Destination+":"+targetPort;
                            if(mappings.TryGetValue(key,out var map))
                            {
                                SwapAddresses(packet);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(p.Tcp),map.Port);address[10]&=0xfd;
                            }
                        }
                        else
                        {
                            string key=p.Destination+":"+sourcePort;
                            bool syn=(packet[p.Tcp+13]&0x12)==2;
                            if(syn)
                            {
                                int pid=TcpOwner.Find(sourcePort,p.Destination);
                                bool testConnection=pid==testPid&&testPid!=0&&(mappings.TryGetValue(key,out var existing)&&existing.ProcessId==pid||Interlocked.CompareExchange(ref testClaimed,1,0)==0);
                                if(pid!=0&&(testConnection||testPid==0&&TcpOwner.IsTelegram(pid)))
                                {
                                    mappings[key]=new(p.Destination,targetPort,DateTime.UtcNow,pid);
                                    Emit($"TELEGRAM_REDIRECT {p.Destination}:{targetPort} pid={pid}");
                                }
                                else mappings.TryRemove(key,out _);
                            }
                            if(mappings.ContainsKey(key))
                            {
                                SwapAddresses(packet);BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(p.Tcp+2),Port);address[10]&=0xfd;
                            }
                        }
                    }
                }
                catch(Exception ex){Emit("TELEGRAM_PACKET_ERROR "+ex.Message);}
                Divert.WinDivertHelperCalcChecksums(packet,count,address,0);
                if(!Divert.WinDivertSend(handle,packet,count,out _,address))throw new Win32Exception(Marshal.GetLastWin32Error(),"Telegram packet send");
                if(mappings.Count>4096)foreach(var entry in mappings.Where(x=>DateTime.UtcNow-x.Value.Seen>TimeSpan.FromHours(1)).ToArray())mappings.TryRemove(entry.Key,out _);
            }
            if(!ct.IsCancellationRequested)throw new Win32Exception(Marshal.GetLastWin32Error(),"Telegram packet receive");
        }
        finally
        {
            listener.Stop();foreach(var client in clients.Values)client.Dispose();
            try{accept.Wait(2000);}catch(AggregateException){}
            Dispose();
        }
    }
    private async Task Accept(CancellationToken ct)
    {
        try
        {
            while(!ct.IsCancellationRequested)
            {
                var client=await listener.AcceptTcpClientAsync(ct);client.NoDelay=true;
                var remote=(IPEndPoint)client.Client.RemoteEndPoint!;string key=remote.Address+":"+remote.Port;
                if(!mappings.TryGetValue(key,out var map)){client.Dispose();continue;}
                int id=Interlocked.Increment(ref nextClient);clients[id]=client;
                _=Task.Run(async()=>
                {
                    try{await TelegramTransport.Bridge(client,map.Destination,Emit,ct,map.Port);}
                    catch(OperationCanceledException){}
                    catch(Exception ex){Emit($"TELEGRAM_FAIL DC{TelegramTransport.DcForIp(map.Destination)} {ex.Message} / {ex.GetBaseException().Message}");}
                    finally{client.Dispose();clients.TryRemove(id,out _);}
                },CancellationToken.None);
            }
        }
        catch(OperationCanceledException){}
        catch(SocketException)when(ct.IsCancellationRequested){}
        catch(ObjectDisposedException){}
    }
    private static void SwapAddresses(byte[] packet)
    {
        for(int i=0;i<4;i++)(packet[12+i],packet[16+i])=(packet[16+i],packet[12+i]);
    }
    private void Emit(string message)=>Log?.Invoke(DateTime.Now.ToString("HH:mm:ss ")+message);
    public void Dispose(){listener.Stop();if(handle!=IntPtr.Zero&&handle!=new IntPtr(-1)){Divert.WinDivertClose(handle);handle=IntPtr.Zero;}}
}

