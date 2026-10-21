using System.Diagnostics;
using System.Text.Json;
namespace DPIUnlocker;
internal static class Benchmark
{
    internal record Result(int Mode,string Host,int ExitCode,string Output,string Error);
    public static async Task<int> Run(bool quick=false)
    {
        string root=AppContext.BaseDirectory;
        var all=new List<Result>();
        string[] targets=quick?["www.youtube.com","github.com","rr4---sn-hgn7rn7r.googlevideo.com"]:["www.youtube.com","x.com","www.instagram.com","www.pornhub.com","github.com","www.microsoft.com","rr4---sn-hgn7rn7r.googlevideo.com"];
        foreach(int mode in quick?new[]{5,6}:new[]{4,0,1,3,2,5,6,-1})
        {
            using var cts=new CancellationTokenSource();
            using var engine=new PacketEngine(mode);
            string log=Path.Combine(root,"benchmark.log");
            engine.Log+=s=> {lock(all) File.AppendAllText(log,s+Environment.NewLine);};
            Task worker=Task.Run(()=>engine.Run(cts.Token));
            await Task.Delay(500);
            if(worker.IsCompleted){await worker;return 1;}
            try
            {
                var results=await Task.WhenAll(targets.Select(async host=>
                {
                    var psi=new ProcessStartInfo("curl.exe"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
                    foreach(string arg in new[]{"--noproxy","*","--connect-timeout","6","--max-time","12","-sS","-o","NUL","-w","%{http_code} ip=%{remote_ip} bytes=%{size_download} connect=%{time_connect} tls=%{time_appconnect} total=%{time_total}",$"https://{host}/"})psi.ArgumentList.Add(arg);
                    using var proc=Process.Start(psi)!;
                    var stdout=proc.StandardOutput.ReadToEndAsync();var stderr=proc.StandardError.ReadToEndAsync();
                    await proc.WaitForExitAsync();
                    return new Result(mode,host,proc.ExitCode,await stdout,await stderr);
                }));
                all.AddRange(results);
                File.WriteAllText(Path.Combine(root,"benchmark.json"),JsonSerializer.Serialize(all,new JsonSerializerOptions{WriteIndented=true}));
            }
            finally{cts.Cancel();await worker;}
            await Task.Delay(250);
        }
        return 0;
    }
}

