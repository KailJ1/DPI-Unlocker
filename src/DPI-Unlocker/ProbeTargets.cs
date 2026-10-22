namespace DPIUnlocker;
internal sealed record ProbeTarget(string Group,string Name,string Address);
internal static class ProbeTargets
{
    public static readonly ProbeTarget[] All=
    [
        new("Discord","DiscordMain","https://discord.com"),
        new("Discord","DiscordGateway","https://gateway.discord.gg"),
        new("Discord","DiscordCDN","https://cdn.discordapp.com"),
        new("Discord","DiscordUpdates","https://updates.discord.com"),
        new("AI (Smart DNS)","Gemini","https://gemini.google.com/app"),
        new("AI (Smart DNS)","ChatGPT","https://chatgpt.com/"),
        new("AI (Smart DNS)","Claude","https://claude.ai/"),
        new("YouTube","YouTubeWeb","https://www.youtube.com"),
        new("YouTube","YouTubeShort","https://youtu.be"),
        new("YouTube","YouTubeImage","https://i.ytimg.com"),
        new("YouTube","YouTubeVideoRedirect","https://redirector.googlevideo.com"),
        new("Google","GoogleMain","https://www.google.com"),
        new("Google","GoogleGstatic","https://www.gstatic.com"),
        new("Cloudflare","CloudflareWeb","https://www.cloudflare.com"),
        new("Cloudflare","CloudflareCDN","https://cdnjs.cloudflare.com"),
        new("Twitter / X","TwitterWeb","https://twitter.com"),
        new("Twitter / X","XWeb","https://x.com"),
        new("Twitter / X","XApi","https://api.x.com"),
        new("Twitter / X","TwitterStatic","https://abs.twimg.com"),
        new("Twitter / X","TwitterImages","https://pbs.twimg.com"),
        new("Twitter / X","TwitterVideo","https://video.twimg.com"),
        new("Instagram","InstagramWeb","https://www.instagram.com"),
        new("Instagram","InstagramStatic","https://static.cdninstagram.com"),
        new("Telegram Web","TelegramMain","https://telegram.org"),
        new("Telegram Web","TelegramWeb","https://web.telegram.org"),
        new("Telegram Web","TelegramLinks","https://t.me"),
        new("Другие","GitHub","https://github.com"),
        new("Другие","Microsoft","https://www.microsoft.com"),
        new("Другие","Wikipedia","https://ru.wikipedia.org"),
        new("Другие","Reddit","https://www.reddit.com"),
        new("Другие","Twitch","https://www.twitch.tv"),
        new("Другие","SteamStore","https://store.steampowered.com"),
        new("Другие","Pornhub","https://www.pornhub.com"),
        new("Public DNS · PING-only","CloudflareDNS1111","PING:1.1.1.1"),
        new("Public DNS · PING-only","CloudflareDNS1001","PING:1.0.0.1"),
        new("Public DNS · PING-only","GoogleDNS8888","PING:8.8.8.8"),
        new("Public DNS · PING-only","GoogleDNS8844","PING:8.8.4.4"),
        new("Public DNS · PING-only","Quad9DNS9999","PING:9.9.9.9")
    ];
}

