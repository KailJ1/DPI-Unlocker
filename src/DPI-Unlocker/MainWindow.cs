using System.Diagnostics;
namespace DPIUnlocker;
internal sealed class MainWindow : Form
{
    private readonly Button start=new(){Text="Включить",Width=160,Height=42};
    private readonly Button stop=new(){Text="Отключить",Width=160,Height=42,Enabled=false};
    private readonly Button tests=new(){Text="Проверить сайты",Width=180,Height=42};
    private readonly ComboBox modes=new(){DropDownStyle=ComboBoxStyle.DropDownList,Width=330};
    private readonly TextBox output=new(){Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,Font=new Font("Consolas",10)};
    private readonly Label status=new(){Text="Выключено",AutoSize=true,Padding=new Padding(8)};
    private readonly CheckBox quic=new(){Text="QUIC (экспериментально)",AutoSize=true};
    private readonly CheckBox telegram=new(){Text="Telegram автоматически",Checked=true,AutoSize=true};
    private readonly CheckBox doh=new(){Text="DNS через HTTPS",Checked=true,AutoSize=true};
    private readonly Button installService=new(){Text="Установить службу",AutoSize=true,Height=36};
    private readonly Button removeService=new(){Text="Удалить службу",AutoSize=true,Height=36};
    private readonly Button serviceState=new(){Text="Проверить службу",AutoSize=true,Height=36};
    private CancellationTokenSource? cts; private Task? worker;
    private readonly System.Windows.Forms.Timer stateTimer=new(){Interval=1000};
    private bool commandBusy;
    private uint? lastServiceState;
    public MainWindow()
    {
        Text="DPI-Unlocker — экспериментальный DPI bypass"; Width=1050; Height=700; MinimumSize=new Size(850,500);
        var top=new FlowLayoutPanel(){Dock=DockStyle.Top,Height=185,Padding=new Padding(12)};
        modes.Items.AddRange(["Автоматически (по ретрансмитам)","0 · TCP split","1 · Fake SNI + badseq + split","2 · TCP overlap + split","3 · TCP disorder","4 · Пропуск без изменений","5 · Fake SNI + MD5 + badseq","6 · Fake SNI + small badseq","7 · Fake TLS ×6 + MD5 + multisplit","8 · Подмена SNI + MD5 + multidisorder"]); modes.SelectedIndex=0;
        modes.DrawMode=DrawMode.OwnerDrawFixed;
        modes.DrawItem+=(_,e)=>{e.DrawBackground();using var brush=new SolidBrush(e.ForeColor);if(e.Index>=0)e.Graphics.DrawString(modes.Items[e.Index]!.ToString(),modes.Font,brush,e.Bounds);e.DrawFocusRectangle();};
        top.Controls.AddRange([start,stop,tests,modes,quic,telegram,doh,status,new Label(){Text="Без списков доменов · Telegram без ручного прокси · QUIC включается отдельно",AutoSize=true,Margin=new Padding(6,12,0,0)}]);
        Controls.Add(output);Controls.Add(top);
        top.Controls.AddRange([installService,removeService,serviceState]);
        var about=new Button(){Text="О программе",AutoSize=true,Height=36};
        top.Controls.Add(about);
        about.Click+=(_,_)=>ShowAbout();
        installService.Click+=async(_,_)=>await ServiceCommand("--install-service");
        removeService.Click+=async(_,_)=>await ServiceCommand("--uninstall-service");
        serviceState.Click+=(_,_)=>RefreshService();
        stateTimer.Tick+=(_,_)=>{if(!commandBusy)RefreshService(false);};
        stateTimer.Start();
        start.Click+=async(_,_)=>await StartEngine(); stop.Click+=async(_,_)=>await StopEngine(); tests.Click+=(_,_)=>new DiagnosticsWindow().Show(this);
        Shown+=async(_,_)=>{RefreshService();if(Environment.GetCommandLineArgs().Contains("--start"))await StartEngine();};
        FormClosing+=(_,_)=>{stateTimer.Stop();cts?.Cancel();if(worker is not null) try {worker.Wait(3000);}catch{};};
        FormClosed+=(_,_)=>stateTimer.Dispose();
        Add("Прототип на C# с WinDivert. Для перехвата пакетов нужны права администратора.");
        Add("Системный прокси и настройки DNS не меняются. Прокси/VPN могут изменить результаты проверки.");
        Add("Ответ TLS ещё не означает загрузку страницы или видео: используйте проверку сайтов.");
    }
    private void ShowAbout()
    {
        using var dialog=new Form(){Text="О DPI-Unlocker",ClientSize=new Size(480,230),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false};
        var info=new Label(){Text="DPI-Unlocker 1.0.6\nОрганизация: Kriavpn\nCopyright © 2026 Kriavpn\n\nОбход DPI-фильтрации для Windows x64.\nДля работы требуются права администратора.",AutoSize=true,Location=new Point(20,20)};
        var site=new LinkLabel(){Text="https://kriavpn.ru",AutoSize=true,Location=new Point(20,165)};
        site.LinkClicked+=(_,_)=>{try{Process.Start(new ProcessStartInfo("https://kriavpn.ru"){UseShellExecute=true});}catch(Exception ex){MessageBox.Show(dialog,ex.Message);}};
        var close=new Button(){Text="Закрыть",DialogResult=DialogResult.OK,Location=new Point(360,185)};
        dialog.Controls.AddRange([info,site,close]);dialog.AcceptButton=close;dialog.CancelButton=close;dialog.ShowDialog(this);
    }
    private void Add(string text)
    {
        if(IsDisposed||Disposing)return;
        if(InvokeRequired) { try {BeginInvoke(()=>Add(text));}catch(InvalidOperationException){} return; }
        if(output.TextLength>150000) output.Text=output.Text[^75000..];
        output.AppendText(text+Environment.NewLine);
        try { File.AppendAllText(Path.Combine(AppContext.BaseDirectory,"gui.log"),text+Environment.NewLine); } catch(IOException){} catch(UnauthorizedAccessException){}
    }
    private async Task StartEngine()
    {
        if(commandBusy)return;
        if(!Program.IsAdmin)
        {
            try {Process.Start(new ProcessStartInfo(Environment.ProcessPath!,"--start"){UseShellExecute=true,Verb="runas",WorkingDirectory=AppContext.BaseDirectory});Close();}
            catch(Exception ex){Add("Не удалось получить права: "+ex.Message);}
            return;
        }
        if(worker is {IsCompleted:false})return;
        if(WindowsService.GetState()!=0)
        {
            await ServiceCommand("--start-service");return;
        }
        cts=new(); int mode=modes.SelectedIndex-1; bool useQuic=quic.Checked,useTelegram=telegram.Checked,useDoh=doh.Checked;
        start.Enabled=false;stop.Enabled=true;modes.Enabled=false;quic.Enabled=false;telegram.Enabled=false;doh.Enabled=false;status.Text="Включается…";
        worker=Task.Run(async()=>
        {
            try { await EngineHost.Run(new EngineSettings(mode,useTelegram,useDoh,useQuic),Add,cts.Token,()=>{if(!IsDisposed)BeginInvoke(()=>status.Text="Включено");}); } catch(OperationCanceledException)when(cts.IsCancellationRequested){} catch(Exception ex){Add("Ошибка: "+ex.Message);}
            if(!IsDisposed)try{BeginInvoke(()=>{start.Enabled=true;stop.Enabled=false;modes.Enabled=true;quic.Enabled=true;telegram.Enabled=true;doh.Enabled=true;status.Text="Выключено";});}catch{}
        });status.Text="Движок запускается (см. журнал)";
    }
    private async Task StopEngine()
    {
        if(commandBusy)return;
        cts?.Cancel();if(worker is not null)await worker;
        if(WindowsService.GetState() is not (0 or 1))await ServiceCommand("--stop-service");
    }
    private void RefreshService(bool verbose=true)
    {
        if(IsDisposed||Disposing)return;
        try
        {
        uint state=WindowsService.GetState();
        string description=state switch{0=>"не установлена",1=>"остановлена",2=>"запускается",3=>"останавливается",4=>"работает",_=>state.ToString()};
        if(verbose||lastServiceState!=state)Add("Служба: "+description+" · журнал: "+Path.Combine(WindowsService.MachineData,"service.log"));
        lastServiceState=state;
        if(worker is not {IsCompleted:false})
        {
            status.Text=state==0?"Выключено · служба не установлена":"Служба: "+description;
            start.Text=state==4?"Включено":"Включить";
            start.Enabled=!commandBusy&&(state is 0 or 1);stop.Enabled=!commandBusy&&(state is 2 or 4);
            modes.Enabled=quic.Enabled=telegram.Enabled=doh.Enabled=!commandBusy&&(state is 0 or 1);
        }
        installService.Text=state==0?"Установить службу":"Обновить службу";
        removeService.Enabled=!commandBusy&&state!=0;
        }
        catch(Exception ex){status.Text="Ошибка проверки службы";if(verbose)Add(ex.Message);}
    }
    private async Task ServiceCommand(string command)
    {
        if(commandBusy)return;
        commandBusy=true;
        start.Enabled=stop.Enabled=false;
        status.Text=command switch{"--start-service"=>"Служба запускается…","--stop-service"=>"Служба останавливается…","--install-service"=>"Установка / обновление службы…",_=>"Удаление службы…"};
        installService.Enabled=removeService.Enabled=serviceState.Enabled=false;
        try
        {
            if(command=="--install-service")
            {
                cts?.Cancel();if(worker is not null)await worker;
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory,"settings.json"),System.Text.Json.JsonSerializer.Serialize(new EngineSettings(modes.SelectedIndex-1,telegram.Checked,doh.Checked,quic.Checked)));
            }
            var info=new ProcessStartInfo(Environment.ProcessPath!,command){UseShellExecute=true,Verb=Program.IsAdmin?"":"runas",WorkingDirectory=AppContext.BaseDirectory,WindowStyle=ProcessWindowStyle.Hidden};
            using var process=Process.Start(info)!;await process.WaitForExitAsync();
            string resultFile=Path.Combine(Program.DataDir,"service-command.txt");
            if(process.ExitCode!=0)throw new IOException(File.Exists(resultFile)?File.ReadAllText(resultFile):"Команда службы завершилась с кодом "+process.ExitCode);
            Add("Команда службы выполнена.");
        }
        catch(Exception ex){Add("Ошибка службы: "+ex.Message);MessageBox.Show(this,ex.Message,"Не удалось выполнить команду службы",MessageBoxButtons.OK,MessageBoxIcon.Error);}
        finally{commandBusy=false;installService.Enabled=serviceState.Enabled=true;RefreshService();}
    }
}



