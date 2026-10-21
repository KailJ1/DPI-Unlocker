using System.Collections.Concurrent;
using System.Net;
namespace DPIUnlocker;

// Used only to make HTTP/3 fall back to TCP. Never changes DNS or destinations.
internal static class VideoEndpoints
{
    private static readonly ConcurrentDictionary<string,DateTime> endpoints=new();
    internal static bool IsVideoHost(string host)=>host.EndsWith(".googlevideo.com",StringComparison.OrdinalIgnoreCase)||host.EndsWith(".c.youtube.com",StringComparison.OrdinalIgnoreCase)||host.Equals("googlevideo.com",StringComparison.OrdinalIgnoreCase);
    internal static void Observe(string host,string ip)
    {
        if(!IsVideoHost(host)||!IPAddress.TryParse(ip,out var address)||IPAddress.IsLoopback(address))return;
        if(endpoints.Count>4096)foreach(var entry in endpoints.Where(e=>DateTime.UtcNow-e.Value>TimeSpan.FromMinutes(10)))endpoints.TryRemove(entry.Key,out _);
        if(endpoints.Count<8192)endpoints[ip]=DateTime.UtcNow;
    }
    internal static bool IsVideoEndpoint(string ip)=>endpoints.TryGetValue(ip,out var seen)&&DateTime.UtcNow-seen<TimeSpan.FromMinutes(10);
}
