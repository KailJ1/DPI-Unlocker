using System.Diagnostics;
using System.Net.NetworkInformation;
namespace DPIUnlocker;
internal sealed record ProbeResult(ProbeTarget Target,string Status,long Milliseconds,string Detail,bool Answered);
internal static class ProbeRunner
{
    public static async Task Run(Action<ProbeResult> report,CancellationToken ct)
    {
        using var slots=new SemaphoreSlim(6);
        using var handler=new SocketsHttpHandler{UseProxy=false,ConnectTimeout=TimeSpan.FromSeconds(6),AllowAutoRedirect=false};
        using var http=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(10)};
        await Task.WhenAll(ProbeTargets.All.Select(async target=>
        {
            await slots.WaitAsync(ct);
            try {report(await Check(target,http,ct));}
            finally {slots.Release();}
        }));
    }
    private static async Task<ProbeResult> Check(ProbeTarget target,HttpClient http,CancellationToken ct)
    {
        var timer=Stopwatch.StartNew();
        try
        {
            if(target.Address.StartsWith("PING:",StringComparison.Ordinal))
            {
                using var ping=new Ping();
                var reply=await ping.SendPingAsync(target.Address[5..],2500).WaitAsync(ct);
                bool ok=reply.Status==IPStatus.Success;
                return new(target,ok?"PING OK":"PING "+reply.Status,ok?reply.RoundtripTime:timer.ElapsedMilliseconds,"Только ICMP. Ответ DNS-сервера и DNS-запросы не проверяются.",ok);
            }
            using var request=new HttpRequestMessage(HttpMethod.Get,target.Address);
            request.Headers.UserAgent.ParseAdd("DPI-Unlocker-Diagnostics/0.1");
            using var response=await http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,ct);
            int code=(int)response.StatusCode;
            string detail=code switch
            {
                >=200 and <300=>"Получены заголовки HTTPS; ресурсы страницы, видео и авторизация не проверялись.",
                >=300 and <400=>"Сервер ответил перенаправлением; конечный адрес не проверялся.",
                401 or 403=>"HTTPS доступен, сервер отказал в доступе: возможны авторизация или защита от ботов.",
                404=>"HTTPS доступен, корневой путь не найден; для API/CDN это возможно.",
                _=>"Получен HTTP-ответ; работоспособность сервиса этим не подтверждается."
            };
            return new(target,"HTTP "+code,timer.ElapsedMilliseconds,detail,true);
        }
        catch(OperationCanceledException)when(ct.IsCancellationRequested){throw;}
        catch(OperationCanceledException){return new(target,"TIMEOUT",timer.ElapsedMilliseconds,"Таймаут соединения или ответа HTTPS.",false);}
        catch(Exception ex)when(ex is HttpRequestException or PingException or System.Net.Sockets.SocketException)
        {return new(target,"ОШИБКА",timer.ElapsedMilliseconds,ex.GetBaseException().Message,false);}
    }
}

