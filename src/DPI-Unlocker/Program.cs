using System.Security.Principal;
namespace DPIUnlocker;
internal static class Program
{
    public static readonly string DataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DPI-Unlocker");
    public static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    [STAThread]
    static int Main(string[] args)
    {
        Directory.CreateDirectory(DataDir);
        if(args.Contains("--driver-status"))
        {
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"driver-status.txt"),DriverPrerequisites.Report(false));return 0;
        }
        if(args.Contains("--telegram-voice-trial"))return TelegramVoiceTrial.Run(args.Contains("--decoys"));
        if(args.Contains("--telegram-call-probe"))return TelegramCallProbe.Run(args);
        if(args.Contains("--service"))return WindowsService.Dispatch();
        if(args.Any(a=>a is "--install-service" or "--uninstall-service" or "--start-service" or "--stop-service"))
        {
            try
            {
                if(!IsAdmin)throw new UnauthorizedAccessException("Administrator required");
                if(args.Contains("--install-service"))ServiceManager.Install(EngineSettings.Load(Path.Combine(AppContext.BaseDirectory,"settings.json")));
                else if(args.Contains("--uninstall-service"))ServiceManager.Uninstall();
                else if(args.Contains("--start-service"))ServiceManager.Start();else ServiceManager.Stop();
                File.WriteAllText(Path.Combine(DataDir,"service-command.txt"),"OK state="+WindowsService.GetState());return 0;
            }
            catch(Exception ex){File.WriteAllText(Path.Combine(DataDir,"service-command.txt"),ex.ToString());return 1;}
        }
        if(args.Contains("--replace") && IsAdmin)
        {
            string distribution=Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,".."))+Path.DirectorySeparatorChar;
            foreach(var other in System.Diagnostics.Process.GetProcessesByName("DPI-Unlocker"))
            {
                using(other)
                {
                    if(other.Id==Environment.ProcessId)continue;
                    try
                    {
                        string? path=other.MainModule?.FileName;
                        if(path is not null && path.StartsWith(distribution,StringComparison.OrdinalIgnoreCase))
                        {
                            other.CloseMainWindow();other.WaitForExit(6500);
                        }
                    }
                    catch(System.ComponentModel.Win32Exception){}
                }
            }
        }
        if (args.Contains("--self-test")) return SelfTests.Run();
        if (args.Contains("--ai-dns-test")) return AiDnsTest.Run().GetAwaiter().GetResult();
        if(args.Contains("--telegram-bridge-test"))return TelegramBridgeTest.Run(args.Contains("--sustained")).GetAwaiter().GetResult();
        if(args.Contains("--telegram-test"))return TelegramTest.Run().GetAwaiter().GetResult();
        if(args.Contains("--telegram-web-test"))return TelegramWebTest.Run().GetAwaiter().GetResult();
        if(args.Contains("--doh-test"))
        {
            using var doh=new DohResolver();string report=Path.Combine(AppContext.BaseDirectory,"doh-test.txt");
            try
            {
                byte[] query=DnsWire.Query("example.com");byte[] answer=doh.Resolve(query,CancellationToken.None).GetAwaiter().GetResult();
                if(!DnsWire.Matches(query,answer)||answer[0]!=query[0]||answer[1]!=query[1])throw new IOException("DNS mismatch");
                File.WriteAllText(report,$"PASS: pinned-IP HTTPS DoH, certificate validation enabled, DNS question and transaction ID verified; answerBytes={answer.Length}");return 0;
            }
            catch(Exception ex){File.WriteAllText(report,"FAIL "+ex);return 1;}
        }
        if(args.Contains("--probe-sites"))
        {
            var results=new System.Collections.Concurrent.ConcurrentBag<ProbeResult>();
            ProbeRunner.Run(results.Add,CancellationToken.None).GetAwaiter().GetResult();
            File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"probe-results.json"),System.Text.Json.JsonSerializer.Serialize(results.OrderBy(r=>r.Target.Group).ThenBy(r=>r.Target.Name),new System.Text.Json.JsonSerializerOptions{WriteIndented=true}));return 0;
        }
        if (args.Contains("--benchmark"))
        {
            try { return Benchmark.Run(args.Contains("--quick")).GetAwaiter().GetResult(); }
            catch(Exception ex) { File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"benchmark-error.txt"),ex.ToString()); return 1; }
        }
        if(args.Contains("--video-strategy-probe"))
        {
            using var cts=new CancellationTokenSource(TimeSpan.FromSeconds(45));
            using var engine=new PacketEngine(4,p=>int.TryParse(p.Flow.Split('|')[1],out int port)&&port is >=40900 and <=41199&&((port-40900)%16)<=8?(port-40900)%16:4);
            engine.Log+=s=>File.AppendAllText(Path.Combine(AppContext.BaseDirectory,"video-strategy-probe.log"),s+Environment.NewLine);
            engine.Run(cts.Token);return 0;
        }
        if (args.Contains("--engine"))
        {
            using var cts = new CancellationTokenSource();
            int mode = GetInt(args, "--mode", -1), seconds = GetInt(args, "--seconds", 120);
            if (mode is < -1 or > 8 || seconds is < 1 or > 86400) return 2;
            cts.CancelAfter(TimeSpan.FromSeconds(seconds));
            string log = Path.Combine(AppContext.BaseDirectory, "engine.log");
            using var engine = new PacketEngine(mode);
            engine.Log += s => File.AppendAllText(log, s + Environment.NewLine);
            try { engine.Run(cts.Token); return 0; }
            catch (Exception ex) { File.AppendAllText(log, "FATAL " + ex + Environment.NewLine); return 1; }
        }
        ApplicationConfiguration.Initialize();
        if(args.Contains("--render-ui"))
        {
            using var form=new MainWindow();form.Show();Application.DoEvents();
            using var bitmap=new Bitmap(form.Width,form.Height);form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height));
            bitmap.Save(Path.Combine(AppContext.BaseDirectory,"ui-preview.png"));return 0;
        }
        if(args.Contains("--render-diagnostics"))
        {
            using var form=new DiagnosticsWindow();form.Show();Application.DoEvents();
            using var bitmap=new Bitmap(form.Width,form.Height);form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height));
            bitmap.Save(Path.Combine(AppContext.BaseDirectory,"diagnostics-preview.png"));return 0;
        }
        Application.Run(new MainWindow());
        return 0;
    }
    private static int GetInt(string[] args, string flag, int fallback)
    {
        int i = Array.IndexOf(args, flag);
        return i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out int n) ? n : fallback;
    }
}

