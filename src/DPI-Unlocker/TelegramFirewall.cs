namespace DPIUnlocker;
internal sealed class TelegramFirewall : IDisposable
{
    private readonly string name="DPI-Unlocker Telegram Bridge "+Environment.ProcessId;
    private dynamic? policy;
    public TelegramFirewall()
    {
        policy=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!);
        dynamic rule=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule")!)!;
        rule.Name=name;rule.Description="Temporary rule for transparent Telegram TCP reflection; removed when DPI-Unlocker stops.";
        rule.ApplicationName=Environment.ProcessPath!;rule.Direction=1;rule.Protocol=6;rule.LocalPorts="18243";
        rule.RemoteAddresses="149.154.160.0/20,91.108.0.0/16,91.105.192.0/24";
        rule.Action=1;rule.Enabled=true;rule.Profiles=7;
        policy!.Rules.Add(rule);
    }
    public void Dispose(){if(policy is not null){try{policy.Rules.Remove(name);}catch(System.Runtime.InteropServices.COMException){}policy=null;}}
}

