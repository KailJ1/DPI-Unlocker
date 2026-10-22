using System.Diagnostics;
using System.Text.Json;
namespace DPIUnlocker;
internal static class ServiceManager
{
    public static readonly string InstallDir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"DPI-Unlocker");
    private static void Sc(params string[] args)
    {
        var info=new ProcessStartInfo("sc.exe"){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true};
        foreach(string arg in args)info.ArgumentList.Add(arg);
        using var process=Process.Start(info)!;string output=process.StandardOutput.ReadToEnd()+process.StandardError.ReadToEnd();process.WaitForExit();
        if(process.ExitCode!=0)throw new IOException("sc.exe "+string.Join(' ',args)+": "+output);
    }
    public static void Wait(uint expected)
    {
        var timer=Stopwatch.StartNew();
        while(WindowsService.GetState()!=expected)
        {
            if(expected==4&&WindowsService.GetState()==1)
            {
                string log=Path.Combine(WindowsService.MachineData,"service.log");
                string detail=File.Exists(log)?File.ReadLines(log).LastOrDefault(line=>line.Contains(" FATAL ")||line.Contains("SERVICE_FATAL"))??"Причина записана в журнал службы.":"Журнал службы ещё не создан.";
                throw new IOException("Служба остановилась при запуске.\n"+detail);
            }
            if(timer.Elapsed>TimeSpan.FromSeconds(30))throw new TimeoutException("Service state timeout: "+expected);
            Thread.Sleep(200);
        }
    }
    public static void Stop()
    {
        uint state=WindowsService.GetState();if(state is 0 or 1)return;
        if(state!=3)Sc("stop",WindowsService.Name);Wait(1);
    }
    public static void Start(){if(WindowsService.GetState()==4)return;Sc("start",WindowsService.Name);Wait(4);}
    public static void Install(EngineSettings settings)
    {
        if(!Program.IsAdmin)throw new UnauthorizedAccessException("Administrator required");
        foreach(string name in new[]{"DPI-Unlocker.exe","WinDivert.dll","WinDivert64.sys","WinDivert-LICENSE.txt"})
            if(!File.Exists(Path.Combine(AppContext.BaseDirectory,name)))throw new FileNotFoundException("В сборке отсутствует необходимый файл; служба не остановлена: "+name);
        Stop();Directory.CreateDirectory(InstallDir);
        foreach(string name in new[]{"DPI-Unlocker.exe","WinDivert.dll","WinDivert64.sys","WinDivert-LICENSE.txt"})
        {
            string source=Path.Combine(AppContext.BaseDirectory,name),target=Path.Combine(InstallDir,name);
            if(!source.Equals(target,StringComparison.OrdinalIgnoreCase))
            {
                bool identical=false;
                if(File.Exists(target))
                {
                    using var sourceStream=File.OpenRead(source);using var targetStream=File.OpenRead(target);
                    identical=System.Security.Cryptography.SHA256.HashData(sourceStream).SequenceEqual(System.Security.Cryptography.SHA256.HashData(targetStream));
                }
                if(!identical)File.Copy(source,target,true);
            }
        }
        settings.Save(Path.Combine(InstallDir,"settings.json"));
        string command="\""+Path.Combine(InstallDir,"DPI-Unlocker.exe")+"\" --service";
        Sc(WindowsService.GetState()==0?"create":"config",WindowsService.Name,"binPath=",command,"start=","auto","obj=","LocalSystem","DisplayName=","DPI-Unlocker");
        Sc("description",WindowsService.Name,"DPI-Unlocker background packet engine");
        Sc("failure",WindowsService.Name,"reset=","86400","actions=","restart/5000/restart/15000/restart/60000");
        Sc("failureflag",WindowsService.Name,"1");Start();
    }
    public static void Uninstall(){Stop();if(WindowsService.GetState()!=0)Sc("delete",WindowsService.Name);}
}

