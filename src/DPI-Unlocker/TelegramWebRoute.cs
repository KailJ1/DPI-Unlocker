using System.Buffers.Binary;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
namespace DPIUnlocker;

// Connection-level failover to alternative edge addresses. DNS answers and
// the TLS byte stream remain unchanged; the client authenticates the hostname.
internal sealed class TelegramWebRoute : IDisposable
{
    private readonly Dictionary<string, string> map = new();
    private readonly Dictionary<string, byte[]> origBytes = new();
    private readonly Dictionary<string, byte[]> altBytes = new();
    private readonly bool immediate;
    private readonly short priority;
    private readonly Dictionary<string, Route> routes = new();
    private IntPtr handle;

    private sealed class Route
    {
        public uint Sequence;
        public int Syns;
        public bool Alternative;
        public bool Established;
        public DateTime Seen;
        public string TargetOriginal = "";
        public string TargetAlternative = "";
    }

    public event Action<string>? Log;

    public TelegramWebRoute(string original = "149.154.167.99", string alternative = "149.154.167.220", bool immediate = false, short priority = 200)
        : this([(original, alternative)], immediate, priority) { }

    public TelegramWebRoute(IEnumerable<(string Original, string Alternative)> pairs, bool immediate = true, short priority = 40)
    {
        this.immediate = immediate;
        this.priority = priority;
        foreach (var (orig, alt) in pairs)
        {
            map[orig] = alt;
            origBytes[orig] = IPAddress.Parse(orig).GetAddressBytes();
            altBytes[alt] = IPAddress.Parse(alt).GetAddressBytes();
        }
    }

    public void Run(CancellationToken ct)
    {
        string origFilter = string.Join(" or ", map.Keys.Select(k => $"ip.DstAddr == {k}"));
        string srcFilter = string.Join(" or ", altBytes.Keys.Concat(map.Keys).Distinct().Select(k => $"ip.SrcAddr == {k}"));
        string filter = $"!loopback and !impostor and ip and tcp and ((outbound and ({origFilter}) and (tcp.DstPort == 443 or tcp.DstPort == 80)) or (inbound and ({srcFilter}) and (tcp.SrcPort == 443 or tcp.SrcPort == 80)))";
        handle = Divert.WinDivertOpen(filter, 0, priority, 0);
        if (handle == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Telegram web route");
        using var cancel = ct.Register(() => Divert.WinDivertShutdown(handle, 1));
        byte[] packet = new byte[65535], address = new byte[80];
        foreach (var (orig, alt) in map)
            Emit(immediate ? $"CDN_ROUTE: {orig} -> {alt}; TLS stream unchanged" : $"TELEGRAM_WEB: failover enabled for {orig} -> {alt}");
        try
        {
            while (Divert.WinDivertRecv(handle, packet, (uint)packet.Length, out uint count, address))
            {
                var p = Packets.Parse(packet, (int)count); bool drop = false;
                if (p is not null)
                {
                    bool outbound = (address[10] & 2) != 0;
                    ushort source = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(p.Tcp)), target = BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(p.Tcp + 2));
                    string srcIp = new IPAddress(packet.AsSpan(12, 4)).ToString();
                    string dstIp = new IPAddress(packet.AsSpan(16, 4)).ToString();
                    string key = outbound ? srcIp + ":" + source + ":" + target : dstIp + ":" + target + ":" + source;
                    if (outbound)
                    {
                        bool syn = (packet[p.Tcp + 13] & 0x12) == 2;
                        if (syn)
                        {
                            if (!routes.TryGetValue(key, out var state) || state.Sequence != p.Seq)
                            {
                                state = new()
                                {
                                    Sequence = p.Seq,
                                    Seen = DateTime.UtcNow,
                                    Alternative = immediate,
                                    TargetOriginal = dstIp,
                                    TargetAlternative = map.GetValueOrDefault(dstIp, "")
                                };
                                routes[key] = state;
                            }
                            state.Syns++;
                            if (state.Syns >= 2 && !state.Established && !state.Alternative && !string.IsNullOrEmpty(state.TargetAlternative))
                            {
                                state.Alternative = true;
                                Emit($"TELEGRAM_WEB_FAILOVER {state.TargetOriginal} -> {state.TargetAlternative}");
                            }
                        }
                        if (routes.TryGetValue(key, out var route) && route.Alternative && altBytes.TryGetValue(route.TargetAlternative, out var altBytesVal))
                        {
                            route.Seen = DateTime.UtcNow;
                            altBytesVal.CopyTo(packet, 16);
                        }
                    }
                    else if (routes.TryGetValue(key, out var route))
                    {
                        string from = new IPAddress(packet.AsSpan(12, 4)).ToString();
                        if (route.Alternative && from == route.TargetAlternative && origBytes.TryGetValue(route.TargetOriginal, out var origBytesVal))
                        {
                            origBytesVal.CopyTo(packet, 12);
                            if ((packet[p.Tcp + 13] & 0x12) == 0x12) route.Established = true;
                        }
                        else if (route.Alternative && from == route.TargetOriginal) drop = true;
                        else if (!route.Alternative && from == route.TargetOriginal && (packet[p.Tcp + 13] & 0x12) == 0x12) route.Established = true;
                        route.Seen = DateTime.UtcNow;
                    }
                    if (routes.Count > 4096)
                        foreach (var keyToRemove in routes.Where(x => DateTime.UtcNow - x.Value.Seen > TimeSpan.FromMinutes(5)).Select(x => x.Key).ToArray())
                            routes.Remove(keyToRemove);
                }
                if (drop) continue;
                Divert.WinDivertHelperCalcChecksums(packet, count, address, 0);
                if (!Divert.WinDivertSend(handle, packet, count, out _, address)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Telegram web route send");
            }
            if (!ct.IsCancellationRequested) throw new Win32Exception(Marshal.GetLastWin32Error(), "Telegram web route recv");
        }
        finally { Dispose(); }
    }
    private void Emit(string s) => Log?.Invoke(DateTime.Now.ToString("HH:mm:ss ") + s);
    public void Dispose() { if (handle != IntPtr.Zero && handle != new IntPtr(-1)) { Divert.WinDivertClose(handle); handle = IntPtr.Zero; } }
}
