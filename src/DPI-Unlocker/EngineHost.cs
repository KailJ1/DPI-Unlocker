using System.Text.Json;
namespace DPIUnlocker;
internal sealed record EngineSettings(int Mode=-1,bool Telegram=true,bool Doh=true,bool Quic=false,bool DiscordVoice=true,bool Gemini=false,bool ChatGpt=false,int SmartDns=0,bool Ai=false)
{
    public bool EffectiveAi => Ai || Gemini || ChatGpt;

    public void Save(string path)
    {
        File.WriteAllText(path,JsonSerializer.Serialize(this));
    }
    public static EngineSettings Load(string path)
    {
        var settings=File.Exists(path)?JsonSerializer.Deserialize<EngineSettings>(File.ReadAllText(path))??new():new();
        if(settings.Mode is < -1 or > 8)throw new InvalidDataException("Invalid strategy in service settings");
        if(settings.SmartDns is <0 or >3)throw new InvalidDataException("Invalid Smart DNS provider");
        return settings;
    }
}
internal static class EngineHost
{
    public static async Task Run(EngineSettings settings,Action<string> log,CancellationToken ct,Action? ready=null)
    {
        var ai=new AiRoutes(settings.EffectiveAi);
        if(!ai.Enabled)AiHostsFile.Cleanup();
        log(DriverPrerequisites.Report(true));
        // Initialize WFP before opening the independent module handles.
        IntPtr bootstrap=Divert.WinDivertOpen("false",0,300,5);
        if(bootstrap==new IntPtr(-1))throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error(),"Не удалось инициализировать WinDivert");
        using var bootstrapLifetime=new BootstrapHandle(bootstrap);
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);
        int expected=6+(settings.DiscordVoice?1:0)+(settings.Doh||ai.Enabled?1:0)+(settings.Telegram?2:0)+(ai.Enabled?1:0);
        var started=new System.Collections.Concurrent.ConcurrentDictionary<string,byte>();
        void Report(string name,string message)
        {
            log(message);
            if((message.Contains("RUNNING mode=")||message.Contains("DNS: прозрачный")||message.Contains("TELEGRAM: прозрачный")||message.Contains("TELEGRAM_WEB:")||message.Contains("CDN_ROUTE:")||message.StartsWith("VIDEO_ROUTES:")||message.StartsWith("TELEGRAM_VOICE:")||message.StartsWith("DISCORD_VOICE:")||message.StartsWith("QUIC:")||message.StartsWith("AI_HOSTS_READY:"))&&started.TryAdd(name,0)&&started.Count==expected)ready?.Invoke();
        }
        Task Start(string name,Action<CancellationToken> run)=>Task.Run(()=>
        {
            try{run(stop.Token);if(!stop.IsCancellationRequested)throw new IOException(name+" stopped unexpectedly");}
            catch(Exception ex)when(!stop.IsCancellationRequested){log(name+" FATAL "+ex);stop.Cancel();throw;}
        },CancellationToken.None);
        var tasks=new List<Task>();
        if(ai.Enabled)tasks.Add(Start("Smart DNS hosts",token=>new AiHosts(ai,settings.SmartDns).Run(s=>Report("AI hosts",s),token).GetAwaiter().GetResult()));
        if(settings.DiscordVoice)tasks.Add(Start("Discord voice",token=>{using var e=new DiscordVoiceEngine();e.Log+=s=>Report("Discord",s);e.Run(token);}));
        tasks.Add(Start("TCP",token=>{using var e=new PacketEngine(settings.Mode,ai:ai);e.Log+=s=>Report("TCP",s);e.Run(token);}));
        foreach(var edge in new[]{(Original:"157.240.205.174",Alternative:"157.240.205.63"),(Original:"31.13.72.174",Alternative:"31.13.72.53")})
            tasks.Add(Start("Instagram "+edge.Original,token=>{using var e=new TelegramWebRoute(edge.Original,edge.Alternative,true);e.Log+=s=>Report(edge.Original,s);e.Run(token);}));
        tasks.Add(Start("WhatsApp web",token=>{using var e=new TelegramWebRoute("157.240.205.60","57.144.253.32",true);e.Log+=s=>Report("WhatsApp web",s);e.Run(token);}));
        tasks.Add(Start("WhatsApp media",token=>{using var e=new TelegramWebRoute("31.13.72.52","57.144.253.32",true);e.Log+=s=>Report("WhatsApp media",s);e.Run(token);}));
        if(settings.Doh||ai.Enabled)tasks.Add(Start("DNS",token=>{using var e=new DnsEngine(ai,settings.Doh,settings.SmartDns);e.Log+=s=>Report("DNS",s);e.Run(token);}));
        if(settings.Telegram)
        {
            tasks.Add(Start("Telegram",token=>{using var e=new TelegramRedirector();e.Log+=s=>Report("Telegram",s);e.Run(token);}));
            var telegramWebPairs=new[]
            {
                ("149.154.167.99","149.154.167.220"),
                ("149.154.165.133","149.154.167.220"),
                ("149.154.165.137","149.154.167.220"),
                ("149.154.164.24","149.154.167.220"),
                ("149.154.164.25","149.154.167.220"),
                ("149.154.175.204","149.154.167.220"),
                ("149.154.175.205","149.154.167.220"),
                ("149.154.171.236","149.154.167.220"),
                ("149.154.171.237","149.154.167.220")
            };
            tasks.Add(Start("Telegram Web",token=>{using var e=new TelegramWebRoute(telegramWebPairs,immediate:true,priority:40);e.Log+=s=>Report("Web",s);e.Run(token);}));
        }
        tasks.Add(Start("QUIC",token=>{using var e=new QuicEngine(settings.Quic,ai);e.Log+=s=>Report("QUIC",s);e.Run(token);}));
        try{await Task.WhenAll(tasks);}finally{stop.Cancel();}
    }
    private sealed class BootstrapHandle(IntPtr handle):IDisposable
    {public void Dispose()=>Divert.WinDivertClose(handle);}
}


