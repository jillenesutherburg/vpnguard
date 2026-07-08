using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace VpnGuard.Tray;

// ---------------------------------------------------------------------------
// Модель config.yaml Go-службы (internal/config/config.go) — поля 1:1.
// ВНИМАНИЕ: пересохранение из форм теряет YAML-комментарии (round-trip
// через модель). Ручные правки с комментариями — через «Открыть конфиг».
// ---------------------------------------------------------------------------

public sealed class GuardConfig
{
    public KillswitchSection Killswitch { get; set; } = new();
    public OpenVpnSection Openvpn { get; set; } = new();

    [YamlMember(Alias = "stop_tunnels_on_vpn_down")]
    public bool? StopTunnelsOnVpnDown { get; set; } = true;

    public List<TunnelEntry> Tunnels { get; set; } = new();

    // ------------------------------------------------------------------ I/O

    public static string Dir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VPNGuard");

    public static string ConfigPath => Path.Combine(Dir, "config.yaml");
    public static string LogPath => Path.Combine(Dir, "vpnguard.log");

    private static IDeserializer Reader => new DeserializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    private static ISerializer Writer => new SerializerBuilder()
        .WithNamingConvention(UnderscoredNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitNull)
        .Build();

    public static GuardConfig Load()
    {
        GuardConfig cfg;
        if (!File.Exists(ConfigPath))
            cfg = new GuardConfig(); // служба создаст пример через `vpnguard init`
        else
            cfg = Reader.Deserialize<GuardConfig>(File.ReadAllText(ConfigPath)) ?? new GuardConfig();

        cfg.Normalize();
        return cfg;
    }

    /// <summary>
    /// YamlDotNet оставляет отсутствующие в YAML секции и коллекции равными null.
    /// Приводим всё к безопасным значениям, чтобы формы могли перебирать списки
    /// без проверок на null (иначе foreach по null → NullReferenceException).
    /// </summary>
    private void Normalize()
    {
        Killswitch ??= new KillswitchSection();
        Openvpn ??= new OpenVpnSection();
        Killswitch.AllowedApps ??= new List<string>();
        Killswitch.TunnelInterfaces ??= new List<string>();
        if (Killswitch.TunnelInterfaces.Count == 0)
            Killswitch.TunnelInterfaces = new List<string> { "OpenVPN", "TAP", "Wintun" };
        if (string.IsNullOrWhiteSpace(Killswitch.DnsWhenDown))
            Killswitch.DnsWhenDown = "svchost";
        if (string.IsNullOrWhiteSpace(Killswitch.AppPolicy))
            Killswitch.AppPolicy = "all";
        Tunnels ??= new List<TunnelEntry>();
        foreach (var t in Tunnels)
            t.Args ??= new List<string>();
    }

    public void Save()
    {
        Directory.CreateDirectory(Dir);
        var tmp = ConfigPath + ".tmp";
        File.WriteAllText(tmp, Writer.Serialize(this));
        File.Move(tmp, ConfigPath, overwrite: true);
    }
}

public sealed class KillswitchSection
{
    public bool Enabled { get; set; } = true;

    /// <summary>false = мягкий режим (динамическая WFP-сессия), true = железный (persistent).</summary>
    public bool Persistent { get; set; }

    [YamlMember(Alias = "allow_lan")]
    public bool AllowLan { get; set; }

    /// <summary>off | svchost | all — доступ к порту 53, когда туннелей нет.</summary>
    [YamlMember(Alias = "dns_when_down")]
    public string DnsWhenDown { get; set; } = "svchost";

    /// <summary>all | allowlist</summary>
    [YamlMember(Alias = "app_policy")]
    public string AppPolicy { get; set; } = "all";

    [YamlMember(Alias = "allowed_apps")]
    public List<string> AllowedApps { get; set; } = new();

    /// <summary>Привязывать permit VPN-сервера к openvpn.exe (app-id). По умолчанию false — надёжнее для коннекта.</summary>
    [YamlMember(Alias = "lock_endpoint_to_app")]
    public bool LockEndpointToApp { get; set; }

    [YamlMember(Alias = "tunnel_interfaces")]
    public List<string> TunnelInterfaces { get; set; } = new() { "OpenVPN", "TAP", "Wintun" };
}

public sealed class OpenVpnSection
{
    public string Config { get; set; } = @"C:\Program Files\OpenVPN\config\client.ovpn";
    public string Binary { get; set; } = @"C:\Program Files\OpenVPN\bin\openvpn.exe";
    public string Management { get; set; } = "";

    [YamlMember(Alias = "management_password")]
    public string ManagementPassword { get; set; } = "";
}

public sealed class TunnelEntry
{
    public string Name { get; set; } = "";
    public string Script { get; set; } = "";
    public List<string>? Args { get; set; }
    public bool? Autostart { get; set; } = true;

    [YamlMember(Alias = "restart_delay_seconds")]
    public int RestartDelaySeconds { get; set; } = 5;

    public CheckEntry? Check { get; set; }
}

public sealed class CheckEntry
{
    public string Type { get; set; } = "tcp";
    public string Target { get; set; } = "";

    [YamlMember(Alias = "interval_seconds")]
    public int IntervalSeconds { get; set; } = 15;

    [YamlMember(Alias = "timeout_seconds")]
    public int TimeoutSeconds { get; set; } = 3;

    [YamlMember(Alias = "fail_threshold")]
    public int FailThreshold { get; set; } = 2;
}
