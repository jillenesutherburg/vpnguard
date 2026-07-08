using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Security.Principal;

namespace VpnGuard.Tray;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        using var mutex = new Mutex(true, "VpnGuardTray", out bool createdNew);
        if (!createdNew)
        {
            MessageBox.Show("VPNGuard уже запущен (иконка в трее).", "VPNGuard",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayAppContext());
    }
}

public sealed class TrayAppContext : ApplicationContext
{
    private const string TaskName = "VPNGuard Tray";

    private readonly NotifyIcon _icon;
    private readonly System.Windows.Forms.Timer _timer;

    private readonly ToolStripMenuItem _miStatus;
    private readonly ToolStripMenuItem _miTunnels;
    private readonly ToolStripMenuItem _miToggle;

    private ServiceStatus? _last;
    private TrayColor _lastColor = TrayColor.Unknown;

    private enum TrayColor { Unknown, Disabled, Blocked, Connected }

    public TrayAppContext()
    {
        _miStatus = new ToolStripMenuItem("Статус: получаю...") { Enabled = false };
        _miTunnels = new ToolStripMenuItem("Туннели: —") { Enabled = false };
        _miToggle = new ToolStripMenuItem("Включить киллсвитч", null, (_, _) => Toggle());

        var menu = new ContextMenuStrip();
        menu.Items.Add(_miStatus);
        menu.Items.Add(_miTunnels);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_miToggle);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Разрешённые приложения...", null, (_, _) => new AllowedAppsForm().ShowDialog()));
        menu.Items.Add(new ToolStripMenuItem("Туннели...", null, (_, _) => new TunnelsForm().ShowDialog()));
        menu.Items.Add(new ToolStripMenuItem("Настройки...", null, (_, _) => new SettingsForm().ShowDialog()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Открыть конфиг (YAML)", null, (_, _) => OpenInNotepad(GuardConfig.ConfigPath)));
        menu.Items.Add(new ToolStripMenuItem("Открыть лог службы", null, (_, _) => OpenInNotepad(GuardConfig.LogPath)));
        menu.Items.Add(new ToolStripMenuItem("Перечитать конфиг", null, (_, _) => Reload()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Автозапуск без UAC (планировщик)", null, (_, _) => SetupAutostart()));
        menu.Items.Add(new ToolStripMenuItem("Убрать автозапуск", null, (_, _) => RemoveAutostart()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Аварийно снять все фильтры (panic)", null, (_, _) => Panic()));
        menu.Items.Add(new ToolStripMenuItem("Выход (служба продолжит работать)", null, (_, _) => ExitApp()));

        _icon = new NotifyIcon
        {
            Icon = DrawIcon(TrayColor.Unknown),
            Text = "VPNGuard",
            Visible = true,
            ContextMenuStrip = menu,
        };
        _icon.DoubleClick += (_, _) => new SettingsForm().ShowDialog();

        if (!IsAdmin())
        {
            _icon.ShowBalloonTip(8000, "VPNGuard",
                "Запущено без прав администратора: управление службой будет недоступно. " +
                "Настройте «Автозапуск без UAC» из-под администратора один раз.",
                ToolTipIcon.Warning);
        }

        _timer = new System.Windows.Forms.Timer { Interval = 2000 };
        _timer.Tick += (_, _) => Refresh();
        _timer.Start();
        Refresh();
    }

    // ------------------------------------------------------------------ статус

    private void Refresh()
    {
        _last = PipeClient.GetStatus();
        TrayColor color;
        string text;

        if (_last == null)
        {
            color = TrayColor.Unknown;
            text = "Служба VPNGuard не отвечает";
            _miStatus.Text = "Статус: служба недоступна (vpnguard service install?)";
            _miTunnels.Text = "Туннели: —";
            _miToggle.Enabled = false;
        }
        else
        {
            _miToggle.Enabled = true;
            if (!_last.KillswitchEnabled)
            {
                color = TrayColor.Disabled;
                text = "Киллсвитч ВЫКЛЮЧЕН — сеть открыта";
                _miStatus.Text = "Статус: киллсвитч выключен";
                _miToggle.Text = "Включить киллсвитч";
            }
            else if (_last.VpnConnected)
            {
                color = TrayColor.Connected;
                text = $"VPN подключён ({_last.AdapterIp})" +
                       (_last.WhitelistMode ? " • белый список" : "") +
                       (_last.Persistent ? " • железный режим" : "");
                _miStatus.Text = $"Статус: ЗАЩИЩЕНО • {_last.AdapterName} • {_last.AdapterIp}";
                _miToggle.Text = "Выключить киллсвитч";
            }
            else
            {
                color = TrayColor.Blocked;
                var dns = _last.DnsWhenDown switch
                {
                    "off" => "DNS: выключен",
                    "all" => "DNS: открыт всем",
                    "svchost" => "DNS: только svchost",
                    _ => null,
                };
                text = "VPN отключён — сеть ЗАБЛОКИРОВАНА" + (dns != null ? $" • {dns}" : "");
                _miStatus.Text = "Статус: VPN нет, трафик заблокирован (кроме реконнекта" +
                                 (dns != null ? $", {dns.ToLowerInvariant()}" : "") + ")";
                _miToggle.Text = "Выключить киллсвитч";
            }

            var s = _last.Scripts;
            _miTunnels.Text = s.Count == 0
                ? "Туннели: нет активных"
                : "Туннели: " + string.Join(", ", s.Select(FormatTunnel));
        }

        _icon.Text = Truncate("VPNGuard — " + text, 127);
        if (color != _lastColor)
        {
            var old = _icon.Icon;
            _icon.Icon = DrawIcon(color);
            old?.Dispose();
            _lastColor = color;
        }
    }

    private static string FormatTunnel(ScriptStatus s)
    {
        // state/detail — опциональное расширение Go-стороны; показываем, если есть
        var mark = s.Running ? "✓" : "✗";
        var extra = !string.IsNullOrEmpty(s.Detail) ? $" ({s.Detail})"
                  : !string.IsNullOrEmpty(s.State) && !s.Running ? $" ({s.State})"
                  : "";
        return $"{s.Name} {mark}{extra}";
    }

    // ------------------------------------------------------------------ действия

    /// <summary>
    /// Вкл/выкл киллсвитча. По договорённости с Go-стороной enable/disable
    /// не пишут конфиг — состояние на диске обновляет трей, затем reload.
    /// </summary>
    private void Toggle()
    {
        if (_last == null) return;
        bool enabling = !_last.KillswitchEnabled;

        if (!enabling &&
            MessageBox.Show("Выключить киллсвитч? Весь трафик пойдёт в обход защиты.",
                "VPNGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        try
        {
            var cfg = GuardConfig.Load();
            cfg.Killswitch.Enabled = enabling;
            cfg.Save();
        }
        catch (Exception ex)
        {
            ShowError("Не удалось обновить config.yaml: " + ex.Message);
            return;
        }

        var r = PipeClient.Send(new PipeRequest { Cmd = "reload" });
        if (!r.Ok) ShowError(r.Error);
        Refresh();
    }

    private void Reload()
    {
        var r = PipeClient.Send(new PipeRequest { Cmd = "reload" });
        if (!r.Ok) ShowError(r.Error);
        else _icon.ShowBalloonTip(2000, "VPNGuard", "Конфиг перечитан службой", ToolTipIcon.Info);
        Refresh();
    }

    private void Panic()
    {
        if (MessageBox.Show(
                "Аварийно снять ВСЕ фильтры VPNGuard (vpnguard panic)?\n" +
                "Сеть станет полностью открытой, включая железный режим.",
                "VPNGuard", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        var exe = FindVpnguardExe();
        if (exe == null)
        {
            ShowError("vpnguard.exe не найден рядом с треем. Запустите вручную: vpnguard panic");
            return;
        }
        if (RunHidden(exe, "panic") == 0)
            _icon.ShowBalloonTip(3000, "VPNGuard", "Все фильтры сняты, сеть открыта.", ToolTipIcon.Info);
        else
            ShowError("vpnguard panic завершился с ошибкой (нужны права администратора).");
        Refresh();
    }

    private static string? FindVpnguardExe()
    {
        var baseDir = Path.GetDirectoryName(Environment.ProcessPath ?? Application.ExecutablePath) ?? "";
        foreach (var candidate in new[]
        {
            Path.Combine(baseDir, "vpnguard.exe"),
            Path.Combine(baseDir, "..", "vpnguard.exe"),
        })
        {
            if (File.Exists(candidate)) return Path.GetFullPath(candidate);
        }
        return null;
    }

    private static void OpenInNotepad(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                MessageBox.Show($"Файл ещё не создан: {path}\n(конфиг создаёт `vpnguard init`)", "VPNGuard");
                return;
            }
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{path}\"") { UseShellExecute = true });
        }
        catch (Exception ex) { ShowError(ex.Message); }
    }

    // ------------------------------------------------------------------ автозапуск без UAC

    private void SetupAutostart()
    {
        if (!IsAdmin())
        {
            ShowError("Нужны права администратора. Запустите VpnGuard.Tray.exe один раз через " +
                      "«Запуск от имени администратора» и повторите.");
            return;
        }
        var exe = Environment.ProcessPath ?? Application.ExecutablePath;
        var args = $"/Create /F /TN \"{TaskName}\" /TR \"\\\"{exe}\\\"\" /SC ONLOGON /RL HIGHEST /IT";
        if (RunHidden("schtasks.exe", args) == 0)
            _icon.ShowBalloonTip(4000, "VPNGuard",
                "Готово: трей будет стартовать при входе в систему с правами администратора без UAC.",
                ToolTipIcon.Info);
        else
            ShowError("Не удалось создать задачу планировщика.");
    }

    private void RemoveAutostart()
    {
        if (RunHidden("schtasks.exe", $"/Delete /F /TN \"{TaskName}\"") == 0)
            _icon.ShowBalloonTip(3000, "VPNGuard", "Автозапуск убран.", ToolTipIcon.Info);
        else
            ShowError("Задача автозапуска не найдена или нет прав.");
    }

    private static int RunHidden(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args)
            { UseShellExecute = false, CreateNoWindow = true })!;
            p.WaitForExit(15000);
            return p.ExitCode;
        }
        catch { return -1; }
    }

    private static bool IsAdmin()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    // ------------------------------------------------------------------ прочее

    private void ExitApp()
    {
        _timer.Stop();
        _icon.Visible = false;
        _icon.Dispose();
        Application.Exit();
    }

    internal static void ShowError(string? msg) =>
        MessageBox.Show(msg ?? "Неизвестная ошибка", "VPNGuard",
            MessageBoxButtons.OK, MessageBoxIcon.Error);

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];

    private static Icon DrawIcon(TrayColor color)
    {
        var (fill, glyph) = color switch
        {
            TrayColor.Connected => (Color.FromArgb(46, 160, 67), "✓"),
            TrayColor.Blocked => (Color.FromArgb(212, 160, 23), "■"),
            TrayColor.Disabled => (Color.FromArgb(110, 110, 110), "○"),
            _ => (Color.FromArgb(190, 50, 50), "!"),
        };

        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var path = new GraphicsPath();
            path.AddPolygon(new[]
            {
                new PointF(16, 1), new PointF(30, 6), new PointF(30, 16),
                new PointF(16, 31), new PointF(2, 16), new PointF(2, 6),
            });
            using var brush = new SolidBrush(fill);
            g.FillPath(brush, path);
            using var pen = new Pen(Color.FromArgb(60, 0, 0, 0), 1.5f);
            g.DrawPath(pen, path);

            using var font = new Font("Segoe UI", 13, FontStyle.Bold, GraphicsUnit.Pixel);
            var size = g.MeasureString(glyph, font);
            using var white = new SolidBrush(Color.White);
            g.DrawString(glyph, font, white, (32 - size.Width) / 2f, (30 - size.Height) / 2f);
        }

        IntPtr h = bmp.GetHicon();
        try { return (Icon)Icon.FromHandle(h).Clone(); }
        finally { DestroyIcon(h); }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);
}
