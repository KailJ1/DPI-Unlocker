namespace DPIUnlocker;

internal sealed class AiRoutes
{
    private readonly bool gemini;
    private readonly bool chatGpt;

    public AiRoutes(bool ai) : this(ai, ai) { }

    public AiRoutes(bool gemini, bool chatGpt)
    {
        this.gemini = gemini;
        this.chatGpt = chatGpt;
    }

    private static readonly string[] GeminiHostsList =
    [
        "gemini.google.com",
        "proactivebackend-pa.googleapis.com",
        "alkalimakersuite-pa.clients6.google.com",
        "geminiweb-pa.clients6.google.com",
        "waa-pa.clients6.google.com",
        "aistudio.google.com",
        "generativeai.google",
        "bard.google.com",
        "makersuite.google.com",
        "deepmind.google",
        "deepmind.com",
        "ai.google.dev"
    ];

    private static readonly string[] ChatGptHostsList =
    [
        "chatgpt.com",
        "chat.openai.com",
        "openai.com",
        "auth.chatgpt.com",
        "auth.openai.com",
        "auth0.openai.com",
        "platform.openai.com",
        "cdn.platform.openai.com",
        "codex-cloud-backend.chatgpt.com",
        "codex-cloud-environments.chatgpt.com",
        "cdn.oaistatic.com",
        "persistent.oaistatic.com",
        "files.oaiusercontent.com",
        "cdn.openai.com",
        "ab.chatgpt.com",
        "ws.chatgpt.com",
        "desktop.chatgpt.com",
        "search.chatgpt.com",
        "tcr9i.chat.openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "ios.chat.openai.com",
        "android.chat.openai.com"
    ];


    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> endpoints = new();

    public bool Enabled => gemini || chatGpt;

    internal string[] Hosts => (gemini ? GeminiHostsList : Array.Empty<string>())
        .Concat(chatGpt ? ChatGptHostsList : Array.Empty<string>())
        .ToArray();

    internal void Observe(byte[] answer)
    {
        foreach (string ip in DnsWire.AddressAnswers(answer))
            endpoints.TryAdd(ip, 0);
    }

    internal bool IsEndpoint(string ip) => endpoints.ContainsKey(ip);

    private static bool InDomain(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    internal static bool IsGeminiHost(string host) =>
        GeminiHostsList.Any(h => h.Equals(host, StringComparison.OrdinalIgnoreCase));

    private static bool IsChatGptHost(string host) =>
        InDomain(host, "chatgpt.com") ||
        InDomain(host, "oaistatic.com") ||
        InDomain(host, "oaiusercontent.com") ||
        host.Equals("openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("chat.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("auth.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("auth0.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("cdn.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("platform.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("cdn.platform.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("tcr9i.chat.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("ios.chat.openai.com", StringComparison.OrdinalIgnoreCase) ||
        host.Equals("android.chat.openai.com", StringComparison.OrdinalIgnoreCase);


    internal bool Matches(string host) =>
        gemini && IsGeminiHost(host) ||
        chatGpt && IsChatGptHost(host);
}
