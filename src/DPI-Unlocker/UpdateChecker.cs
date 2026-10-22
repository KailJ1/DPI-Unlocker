using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text.Json;

namespace DPIUnlocker;

internal static class UpdateChecker
{
    public const string ReleasesUrl = "https://github.com/KailJ1/DPI-Unlocker/releases";
    private const string ApiUrl = "https://api.github.com/repos/KailJ1/DPI-Unlocker/releases/latest";

    public static Version CurrentVersion => typeof(UpdateChecker).Assembly.GetName().Version ?? new Version(1, 0, 7);

    public static async Task<UpdateCheckResult> CheckForUpdatesAsync(CancellationToken ct = default)
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(6) };
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DPI-Unlocker", CurrentVersion.ToString(3)));
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var response = await client.GetAsync(ApiUrl, ct);
            if (response.IsSuccessStatusCode)
            {
                using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                var root = doc.RootElement;
                string tagName = root.TryGetProperty("tag_name", out var tag) ? tag.GetString() ?? "" : "";
                string htmlUrl = root.TryGetProperty("html_url", out var url) ? url.GetString() ?? ReleasesUrl : ReleasesUrl;
                string releaseName = root.TryGetProperty("name", out var n) ? n.GetString() ?? tagName : tagName;

                if (TryParseVersion(tagName, out var latestVersion))
                {
                    bool isNewer = latestVersion > CurrentVersion;
                    return new UpdateCheckResult(true, isNewer, latestVersion, tagName, releaseName, htmlUrl, null);
                }
            }

            // Fallback: Check redirect on GitHub releases/latest URL
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var fallbackClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(6) };
            fallbackClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DPI-Unlocker", CurrentVersion.ToString(3)));
            using var head = await fallbackClient.GetAsync("https://github.com/KailJ1/DPI-Unlocker/releases/latest", ct);
            if (head.Headers.Location is not null)
            {
                string tag = head.Headers.Location.Segments.LastOrDefault()?.Trim('/') ?? "";
                if (TryParseVersion(tag, out var latestVersion))
                {
                    bool isNewer = latestVersion > CurrentVersion;
                    return new UpdateCheckResult(true, isNewer, latestVersion, tag, tag, ReleasesUrl, null);
                }
            }

            return new UpdateCheckResult(false, false, null, null, null, ReleasesUrl, "Не удалось определить версию последнего релиза.");
        }
        catch (Exception ex)
        {
            return new UpdateCheckResult(false, false, null, null, null, ReleasesUrl, ex.Message);
        }
    }

    public static bool TryParseVersion(string? text, out Version version)
    {
        version = new Version(0, 0, 0);
        if (string.IsNullOrWhiteSpace(text)) return false;
        string cleaned = text.Trim();
        if (cleaned.StartsWith('v') || cleaned.StartsWith('V'))
            cleaned = cleaned[1..];
        int dash = cleaned.IndexOf('-');
        if (dash > 0) cleaned = cleaned[..dash];

        string[] parts = cleaned.Split('.');
        if (parts.Length == 1 && int.TryParse(parts[0], out int major))
        {
            version = new Version(major, 0, 0);
            return true;
        }
        if (parts.Length == 2 && int.TryParse(parts[0], out int p1) && int.TryParse(parts[1], out int p2))
        {
            version = new Version(p1, p2, 0);
            return true;
        }
        return Version.TryParse(cleaned, out version!);
    }

    public static void OpenReleasesPage(string? url = null)
    {
        try
        {
            Process.Start(new ProcessStartInfo(url ?? ReleasesUrl) { UseShellExecute = true });
        }
        catch { }
    }
}

internal sealed record UpdateCheckResult(
    bool Success,
    bool IsNewer,
    Version? LatestVersion,
    string? TagName,
    string? ReleaseName,
    string HtmlUrl,
    string? Error);
