using System.Text.Json;
namespace DPIUnlocker;
internal sealed class DiagnosticsWindow : Form
{
    private readonly DataGridView table=new(){Dock=DockStyle.Fill,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,RowHeadersVisible=false,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,SelectionMode=DataGridViewSelectionMode.FullRowSelect};
    private readonly Label progress=new(){Text="Готово к проверке",AutoSize=true,Margin=new Padding(12)};
    private readonly Button run=new(){Text="Проверить всё",Width=150,Height=36};
    private readonly Button cancel=new(){Text="Остановить",Width=130,Height=36,Enabled=false};
    private readonly Dictionary<string,DataGridViewRow> rows=new();
    private readonly List<ProbeResult> results=new();
    private CancellationTokenSource? cts;
    public DiagnosticsWindow()
    {
        Text="DPI-Unlocker — проверка сайтов и ping";Width=1250;Height=800;MinimumSize=new Size(900,550);
        foreach(string title in new[]{"Группа","Проверка","Адрес","Результат","мс","Подробности"})table.Columns.Add(title,title);
        table.Columns[0].FillWeight=85;table.Columns[1].FillWeight=100;table.Columns[2].FillWeight=150;table.Columns[3].FillWeight=65;table.Columns[4].FillWeight=35;table.Columns[5].FillWeight=240;
        foreach(var target in ProbeTargets.All)
        {
            int i=table.Rows.Add(target.Group,target.Name,target.Address,"—","","");rows[target.Name]=table.Rows[i];
        }
        var panel=new FlowLayoutPanel{Dock=DockStyle.Top,Height=95,Padding=new Padding(8)};
        panel.Controls.AddRange([run,cancel,progress,new Label{AutoSize=true,Text="Прямые HTTPS-запросы без системного прокси. HTTP 403/404 — ответ сервера, не подтверждение работы сервиса. DNS-адреса — только ICMP.",Margin=new Padding(4,10,0,0)}]);
        Controls.Add(table);Controls.Add(panel);
        run.Click+=async(_,_)=>await Run();cancel.Click+=(_,_)=>cts?.Cancel();FormClosing+=(_,_)=>cts?.Cancel();
        Shown+=async(_,_)=>await Run();
    }
    private async Task Run()
    {
        if(cts is not null)return;
        cts=new();results.Clear();run.Enabled=false;cancel.Enabled=true;
        foreach(var row in rows.Values){row.Cells[3].Value="Ожидание";row.Cells[4].Value="";row.Cells[5].Value="";row.DefaultCellStyle.BackColor=Color.White;}
        void Report(ProbeResult result)
        {
            if(IsDisposed||Disposing)return;
            try{BeginInvoke(()=>
            {
                if(IsDisposed||Disposing)return;
                results.Add(result);var row=rows[result.Target.Name];row.Cells[3].Value=result.Status;row.Cells[4].Value=result.Milliseconds;row.Cells[5].Value=result.Detail;
                row.DefaultCellStyle.BackColor=!result.Answered?Color.MistyRose:result.Status is "HTTP 200" or "PING OK"?Color.Honeydew:Color.LemonChiffon;
                progress.Text=$"Проверено {results.Count}/{ProbeTargets.All.Length} · ответили {results.Count(r=>r.Answered)}";
            });}catch(InvalidOperationException){}
        }
        try
        {
            await ProbeRunner.Run(Report,cts.Token);
            await Task.Yield();
            Directory.CreateDirectory(Program.DataDir);
            File.WriteAllText(Path.Combine(Program.DataDir,"diagnostics.json"),JsonSerializer.Serialize(results,new JsonSerializerOptions{WriteIndented=true}));
        }
        catch(OperationCanceledException){if(!IsDisposed)progress.Text+=" · остановлено";}
        catch(Exception ex){if(!IsDisposed)progress.Text="Ошибка: "+ex.Message;}
        finally{cts?.Dispose();cts=null;if(!IsDisposed){run.Enabled=true;cancel.Enabled=false;}}
    }
}

