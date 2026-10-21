using Microsoft.Win32;
namespace DPIUnlocker;

internal static class DriverPrerequisites
{
    internal static string? DisabledMessage(string name,int start)
    {
        if(start!=4)return null;
        return name=="BFE"
            ? "Служба Windows BFE (Базовая служба фильтрации) отключена. Без неё WinDivert не работает. Откройте services.msc, проверьте BFE и восстановите её штатный запуск. Если настройка задана администратором, обратитесь к нему."
            : $"Драйвер {name} отключён в Windows (ошибка 1058). Удаление службы DPI-Unlocker не включает драйвер. Запустите Restore-WinDivert.ps1 из новой сборки через PowerShell от администратора, затем повторите запуск.";
    }
    public static string Report(bool failOnDisabled)
    {
        var lines=new List<string>();
        foreach(string name in new[]{"BFE","WinDivert","WinDivert1.4"})
        {
            using var key=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\"+name);
            if(key is null){lines.Add(name+": не зарегистрирована");continue;}
            int start=Convert.ToInt32(key.GetValue("Start",-1));
            lines.Add($"{name}: Start={start} (4 — отключена; 3 — по требованию; 2 — автоматически)");
            // WinDivert1.4 is reported for context; it is not used by this build.
            // WinDivert can mark its temporary SCM registration for deletion while loaded.
            // Start=4 alone does not indicate a broken driver. Let WinDivertOpen decide.
            if(name!="BFE")continue;
            string? error=DisabledMessage(name,start);
            if(failOnDisabled&&error is not null)throw new IOException(error);
        }
        return string.Join(Environment.NewLine,lines);
    }
}
