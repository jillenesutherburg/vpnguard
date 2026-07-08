using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace VpnGuard.Tray;

// ---------------------------------------------------------------------------
// Клиент именованного канала Go-службы VPNGuard.
// Протокол построчного JSON — тот же, что был в C#-службе VpnSentinel;
// Go-сторона (internal/ipc) реализует его байт-в-байт, поэтому имя пайпа
// пока историческое: VpnSentinelService. Переименование — синхронно с
// службой на этапе инсталлятора (см. docs/NOTES-FOR-SERVICE.md).
// ---------------------------------------------------------------------------

public sealed class PipeRequest
{
    [JsonPropertyName("cmd")] public string Cmd { get; set; } = "";
    [JsonPropertyName("arg")] public string? Arg { get; set; }
}

public sealed class PipeResponse
{
    [JsonPropertyName("ok")] public bool Ok { get; set; }
    [JsonPropertyName("error")] public string? Error { get; set; }
    [JsonPropertyName("data")] public JsonElement? Data { get; set; }
}

public sealed class ServiceStatus
{
    [JsonPropertyName("killswitchEnabled")] public bool KillswitchEnabled { get; set; }
    [JsonPropertyName("vpnConnected")] public bool VpnConnected { get; set; }
    [JsonPropertyName("adapterName")] public string? AdapterName { get; set; }
    [JsonPropertyName("adapterIp")] public string? AdapterIp { get; set; }
    [JsonPropertyName("persistent")] public bool Persistent { get; set; }
    [JsonPropertyName("whitelistMode")] public bool WhitelistMode { get; set; }

    /// <summary>off | svchost | all — отдаётся Go-службой (опционально).</summary>
    [JsonPropertyName("dnsWhenDown")] public string? DnsWhenDown { get; set; }

    [JsonPropertyName("scripts")] public List<ScriptStatus> Scripts { get; set; } = new();
}

public sealed class ScriptStatus
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("running")] public bool Running { get; set; }
    [JsonPropertyName("restarts")] public int Restarts { get; set; }

    // Опциональные поля — Go-сторона добавит (см. NOTES-FOR-SERVICE.md);
    // трей показывает их, если они есть, и молчит, если нет.
    [JsonPropertyName("state")] public string? State { get; set; }
    [JsonPropertyName("detail")] public string? Detail { get; set; }
}

public static class PipeClient
{
    public const string PipeName = "VpnSentinelService";

    public static PipeResponse Send(PipeRequest req, int timeoutMs = 2000)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
            pipe.Connect(timeoutMs);

            using var reader = new StreamReader(pipe, leaveOpen: true);
            using var writer = new StreamWriter(pipe, leaveOpen: true) { AutoFlush = true };

            writer.WriteLine(JsonSerializer.Serialize(req));
            var line = reader.ReadLine();
            if (line == null) return Fail("Пустой ответ службы");
            return JsonSerializer.Deserialize<PipeResponse>(line) ?? Fail("Некорректный ответ службы");
        }
        catch (TimeoutException)
        {
            return Fail("Служба VPNGuard не отвечает (установлена и запущена?)");
        }
        catch (Exception ex)
        {
            return Fail(ex.Message);
        }
    }

    public static ServiceStatus? GetStatus()
    {
        var r = Send(new PipeRequest { Cmd = "status" });
        if (!r.Ok || r.Data == null) return null;
        try { return r.Data.Value.Deserialize<ServiceStatus>(); }
        catch { return null; }
    }

    private static PipeResponse Fail(string msg) => new() { Ok = false, Error = msg };
}
