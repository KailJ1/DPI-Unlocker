using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DPIUnlocker;
internal static class WindowsService
{
    public const string Name="DPI-Unlocker";
    public static readonly string MachineData=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"DPI-Unlocker");
    [StructLayout(LayoutKind.Sequential)]internal struct Status{public uint Type,State,Accepted,Win32Exit,SpecificExit,Checkpoint,WaitHint;}
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]private delegate void ServiceMain(uint argc,IntPtr argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]private delegate uint Handler(uint control,uint eventType,IntPtr data,IntPtr context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct Entry{[MarshalAs(UnmanagedType.LPWStr)]public string? Name;public ServiceMain? Main;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool StartServiceCtrlDispatcher([In]Entry[] table);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr RegisterServiceCtrlHandlerEx(string name,Handler handler,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool SetServiceStatus(IntPtr handle,ref Status status);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenSCManager(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]private static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)]private static extern bool QueryServiceStatus(IntPtr service,out Status status);
    [DllImport("advapi32.dll")][return:MarshalAs(UnmanagedType.Bool)]private static extern bool CloseServiceHandle(IntPtr handle);
    private static readonly ServiceMain main=RunService;
    private static readonly Handler handler=Control;
    private static readonly object statusGate=new(),logGate=new();
    private static CancellationTokenSource? stop;
    private static IntPtr statusHandle;
    private static Status current;
    public static int Dispatch()
    {
        if(!StartServiceCtrlDispatcher([new(){Name=Name,Main=main},new()]))throw new Win32Exception(Marshal.GetLastWin32Error(),"StartServiceCtrlDispatcher");return 0;
    }
    public static uint GetState()
    {
        IntPtr scm=OpenSCManager(null,null,1);if(scm==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            IntPtr service=OpenService(scm,Name,4);
            if(service==IntPtr.Zero){int error=Marshal.GetLastWin32Error();if(error==1060)return 0;throw new Win32Exception(error);}
            try{if(!QueryServiceStatus(service,out var status))throw new Win32Exception(Marshal.GetLastWin32Error());return status.State;}
            finally{CloseServiceHandle(service);}
        }
        finally{CloseServiceHandle(scm);}
    }
    private static void RunService(uint argc,IntPtr argv)
    {
        statusHandle=RegisterServiceCtrlHandlerEx(Name,handler,IntPtr.Zero);if(statusHandle==IntPtr.Zero)return;
        stop=new();Set(2,0,30000,1);
        try
        {
            Directory.SetCurrentDirectory(AppContext.BaseDirectory);Directory.CreateDirectory(MachineData);
            var settings=EngineSettings.Load(Path.Combine(AppContext.BaseDirectory,"settings.json"));
            Log("SERVICE_START session="+System.Diagnostics.Process.GetCurrentProcess().SessionId);
            var worker=EngineHost.Run(settings,Log,stop.Token,()=>{if(!stop.IsCancellationRequested)Set(4,5,0,0);});
            while(!worker.Wait(1000))
            {
                if(stop.IsCancellationRequested)Set(3,0,15000,current.Checkpoint+1);
            }
            worker.GetAwaiter().GetResult();Log("SERVICE_STOPPED clean");Set(1,0,0,0);
        }
        catch(Exception ex){Log("SERVICE_FATAL "+ex);Set(1,0,0,0,1066,1);}
        finally{stop.Dispose();stop=null;}
    }
    private static uint Control(uint control,uint eventType,IntPtr data,IntPtr context)
    {
        if(control is 1 or 5){Set(3,0,15000,1);stop?.Cancel();return 0;}
        if(control==4){lock(statusGate)SetServiceStatus(statusHandle,ref current);return 0;}return 120;
    }
    private static void Set(uint state,uint accepted,uint hint,uint checkpoint,uint error=0,uint specific=0)
    {
        lock(statusGate){current=new(){Type=0x10,State=state,Accepted=accepted,WaitHint=hint,Checkpoint=checkpoint,Win32Exit=error,SpecificExit=specific};SetServiceStatus(statusHandle,ref current);}
    }
    private static void Log(string s)
    {
        lock(logGate)
        {
            Directory.CreateDirectory(MachineData);string file=Path.Combine(MachineData,"service.log");
            if(File.Exists(file)&&new FileInfo(file).Length>10_000_000)File.Move(file,file+".1",true);
            File.AppendAllText(file,DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss ")+s+Environment.NewLine);
        }
    }
}

