namespace VpnGuard.Tray;

// ---------------------------------------------------------------------------
// Формы настроек. Все пишут config.yaml (схема Go-службы) и шлют reload.
// ---------------------------------------------------------------------------

public sealed class AllowedAppsForm : Form
{
    private readonly CheckBox _chkAllowlist;
    private readonly ListBox _list;
    private readonly GuardConfig _cfg;

    public AllowedAppsForm()
    {
        _cfg = GuardConfig.Load();

        Text = "VPNGuard — разрешённые приложения";
        Width = 640; Height = 480;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false; MaximizeBox = false;
        FormBorderStyle = FormBorderStyle.FixedDialog;

        _chkAllowlist = new CheckBox
        {
            Text = "Режим белого списка (app_policy: allowlist): через туннель выходят ТОЛЬКО приложения из списка",
            Checked = _cfg.Killswitch.AppPolicy == "allowlist",
            Left = 12, Top = 12, Width = 600, Height = 24,
        };

        _list = new ListBox { Left = 12, Top = 44, Width = 480, Height = 340 };
        foreach (var app in _cfg.Killswitch.AllowedApps) _list.Items.Add(app);

        var btnAdd = new Button { Text = "Добавить...", Left = 504, Top = 44, Width = 110 };
        btnAdd.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Filter = "Программы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Title = "Выберите приложение, которому разрешён выход в сеть через VPN",
            };
            if (dlg.ShowDialog() == DialogResult.OK && !_list.Items.Contains(dlg.FileName))
                _list.Items.Add(dlg.FileName);
        };

        var btnRemove = new Button { Text = "Удалить", Left = 504, Top = 78, Width = 110 };
        btnRemove.Click += (_, _) =>
        {
            if (_list.SelectedIndex >= 0) _list.Items.RemoveAt(_list.SelectedIndex);
        };

        var hint = new Label
        {
            Left = 12, Top = 390, Width = 600, Height = 18, ForeColor = Color.DimGray,
            Text = "DNS через туннель разрешён любому приложению (резолвит svchost) — это учтено Go-службой.",
        };

        var btnSave = new Button { Text = "Сохранить и применить", Left = 380, Top = 412, Width = 160, DialogResult = DialogResult.OK };
        btnSave.Click += (_, _) => Save();
        var btnCancel = new Button { Text = "Отмена", Left = 546, Top = 412, Width = 68, DialogResult = DialogResult.Cancel };

        Controls.AddRange(new Control[] { _chkAllowlist, _list, btnAdd, btnRemove, hint, btnSave, btnCancel });
        AcceptButton = btnSave; CancelButton = btnCancel;
    }

    private void Save()
    {
        try
        {
            _cfg.Killswitch.AppPolicy = _chkAllowlist.Checked ? "allowlist" : "all";
            _cfg.Killswitch.AllowedApps = _list.Items.Cast<string>().ToList();
            _cfg.Save();
            SendReload();
        }
        catch (Exception ex) { TrayAppContext.ShowError("Ошибка сохранения: " + ex.Message); }
    }

    internal static void SendReload()
    {
        var r = PipeClient.Send(new PipeRequest { Cmd = "reload" });
        if (!r.Ok)
            MessageBox.Show("Конфиг сохранён, но служба не ответила: " + r.Error,
                "VPNGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }
}

public sealed class TunnelsForm : Form
{
    private readonly DataGridView _grid;
    private readonly GuardConfig _cfg;

    public TunnelsForm()
    {
        _cfg = GuardConfig.Load();

        Text = "VPNGuard — туннели";
        Width = 900; Height = 470;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false; MaximizeBox = false;
        FormBorderStyle = FormBorderStyle.FixedDialog;

        _grid = new DataGridView
        {
            Left = 12, Top = 12, Width = 860, Height = 330,
            AllowUserToAddRows = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
        };
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "Автостарт", Name = "auto", Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Имя", Name = "name", Width = 130 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Скрипт (.bat/.exe)", Name = "script", Width = 330 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Пауза рестарта, с", Name = "rdelay", Width = 100 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Health-check (host:port)", Name = "check", Width = 200 });

        foreach (var t in _cfg.Tunnels)
            _grid.Rows.Add(t.Autostart ?? true, t.Name, t.Script, t.RestartDelaySeconds, t.Check?.Target ?? "");

        var btnAdd = new Button { Text = "Добавить скрипт...", Left = 12, Top = 352, Width = 140 };
        btnAdd.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Filter = "Скрипты и программы (*.bat;*.cmd;*.exe)|*.bat;*.cmd;*.exe|Все файлы (*.*)|*.*",
                Title = "Скрипт, запускаемый после подключения VPN",
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                _grid.Rows.Add(true, Path.GetFileNameWithoutExtension(dlg.FileName), dlg.FileName, 5, "");
        };

        var btnRemove = new Button { Text = "Удалить строку", Left = 160, Top = 352, Width = 130 };
        btnRemove.Click += (_, _) =>
        {
            if (_grid.SelectedRows.Count > 0) _grid.Rows.Remove(_grid.SelectedRows[0]);
        };

        var hint = new Label
        {
            Left = 12, Top = 384, Width = 860, Height = 34, ForeColor = Color.DimGray,
            Text = "Health-check: TCP-подключение к локальному проброшенному порту (например 127.0.0.1:1080); пусто — только контроль процесса.\n" +
                   "Пауза рестарта — стартовая, при повторных падениях растёт ×2 до 60с. Аргументы (args) правятся через «Открыть конфиг».",
        };

        var btnSave = new Button { Text = "Сохранить и применить", Left = 636, Top = 352, Width = 160, DialogResult = DialogResult.OK };
        btnSave.Click += (_, _) => Save();
        var btnCancel = new Button { Text = "Отмена", Left = 804, Top = 352, Width = 68, DialogResult = DialogResult.Cancel };

        Controls.AddRange(new Control[] { _grid, btnAdd, btnRemove, hint, btnSave, btnCancel });
        CancelButton = btnCancel;
    }

    private void Save()
    {
        try
        {
            // сохраняем args существующих туннелей по имени — грид их не редактирует
            var oldByName = _cfg.Tunnels.ToDictionary(t => t.Name, t => t);

            var list = new List<TunnelEntry>();
            foreach (DataGridViewRow row in _grid.Rows)
            {
                var script = row.Cells["script"].Value?.ToString() ?? "";
                if (string.IsNullOrWhiteSpace(script)) continue;

                var name = row.Cells["name"].Value?.ToString() ?? Path.GetFileNameWithoutExtension(script);
                var target = row.Cells["check"].Value?.ToString()?.Trim() ?? "";
                oldByName.TryGetValue(name, out var old);

                list.Add(new TunnelEntry
                {
                    Name = name,
                    Script = script,
                    Args = old?.Args,
                    Autostart = row.Cells["auto"].Value as bool? ?? true,
                    RestartDelaySeconds = ParseInt(row.Cells["rdelay"].Value, 5),
                    Check = string.IsNullOrEmpty(target)
                        ? null
                        : new CheckEntry
                        {
                            Type = "tcp",
                            Target = target,
                            IntervalSeconds = old?.Check?.IntervalSeconds ?? 15,
                            TimeoutSeconds = old?.Check?.TimeoutSeconds ?? 3,
                            FailThreshold = old?.Check?.FailThreshold ?? 2,
                        },
                });
            }
            _cfg.Tunnels = list;
            _cfg.Save();
            AllowedAppsForm.SendReload();
        }
        catch (Exception ex) { TrayAppContext.ShowError("Ошибка сохранения: " + ex.Message); }
    }

    private static int ParseInt(object? v, int def) =>
        int.TryParse(v?.ToString(), out var n) && n > 0 ? n : def;
}

public sealed class SettingsForm : Form
{
    private readonly GuardConfig _cfg;

    private readonly CheckBox _chkPersistent;
    private readonly CheckBox _chkLan;
    private readonly CheckBox _chkStopTunnels;
    private readonly ComboBox _cmbDns;
    private readonly TextBox _txtBinary;
    private readonly TextBox _txtOvpn;
    private readonly TextBox _txtPatterns;

    public SettingsForm()
    {
        _cfg = GuardConfig.Load();

        Text = "VPNGuard — настройки";
        Width = 680;
        StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false; MaximizeBox = false;
        FormBorderStyle = FormBorderStyle.FixedDialog;

        int y = 12;

        _chkPersistent = Check("«Железный» режим (persistent): фильтры переживают падение/остановку службы и перезагрузку",
            _cfg.Killswitch.Persistent, ref y);
        Hint("Выключено = мягкий режим: при падении службы ОС сама снимает фильтры. Рекомендуется для обкатки.", ref y);

        _chkLan = Check("Разрешить локальную сеть (allow_lan)", _cfg.Killswitch.AllowLan, ref y);

        _chkStopTunnels = Check("Останавливать туннели при падении VPN (stop_tunnels_on_vpn_down)",
            _cfg.StopTunnelsOnVpnDown ?? true, ref y);

        y += 6;
        Controls.Add(new Label { Left = 12, Top = y + 3, Width = 300, Text = "DNS, когда VPN отключён (dns_when_down):" });
        _cmbDns = new ComboBox
        {
            Left = 320, Top = y, Width = 130, DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _cmbDns.Items.AddRange(new object[] { "svchost", "off", "all" });
        _cmbDns.SelectedItem = _cfg.Killswitch.DnsWhenDown is "off" or "all" ? _cfg.Killswitch.DnsWhenDown : "svchost";
        Controls.Add(_cmbDns);
        y += 28;
        Hint("svchost — порт 53 только DNS-службе Windows (умолчание). off — самый строгий: реконнект по кэшу IP. all — порт 53 всем.", ref y);

        y += 6;
        _txtBinary = PathRow("openvpn.exe (openvpn.binary):", _cfg.Openvpn.Binary, ref y);
        _txtOvpn = PathRow("Файл .ovpn (openvpn.config):", _cfg.Openvpn.Config, ref y);

        y += 6;
        Controls.Add(new Label { Left = 12, Top = y, Width = 640, Text = "Паттерны туннельных адаптеров (tunnel_interfaces, по одному на строку):" });
        y += 20;
        _txtPatterns = new TextBox
        {
            Left = 12, Top = y, Width = 640, Height = 58, Multiline = true, ScrollBars = ScrollBars.Vertical,
            Text = string.Join(Environment.NewLine, _cfg.Killswitch.TunnelInterfaces),
        };
        Controls.Add(_txtPatterns);
        y += 66;
        Hint("Сверить имена адаптеров: команда `vpnguard interfaces`. Management-интерфейс OpenVPN правится через «Открыть конфиг».", ref y);

        var btnSave = new Button { Text = "Сохранить и применить", Left = 416, Top = y + 8, Width = 160, DialogResult = DialogResult.OK };
        btnSave.Click += (_, _) => Save();
        var btnCancel = new Button { Text = "Отмена", Left = 584, Top = y + 8, Width = 68, DialogResult = DialogResult.Cancel };
        Controls.Add(btnSave); Controls.Add(btnCancel);
        AcceptButton = btnSave; CancelButton = btnCancel;
        Height = y + 96;
    }

    private CheckBox Check(string text, bool value, ref int y)
    {
        var c = new CheckBox { Left = 12, Top = y, Width = 650, Height = 22, Text = text, Checked = value };
        Controls.Add(c);
        y += 24;
        return c;
    }

    private void Hint(string text, ref int y)
    {
        var l = new Label { Left = 30, Top = y, Width = 630, Height = 16, Text = text, ForeColor = Color.DimGray };
        Controls.Add(l);
        y += 22;
    }

    private TextBox PathRow(string label, string value, ref int y)
    {
        Controls.Add(new Label { Left = 12, Top = y + 3, Width = 210, Text = label });
        var txt = new TextBox { Left = 226, Top = y, Width = 356, Text = value };
        var btn = new Button { Text = "...", Left = 588, Top = y - 1, Width = 30 };
        btn.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { FileName = txt.Text };
            if (dlg.ShowDialog() == DialogResult.OK) txt.Text = dlg.FileName;
        };
        Controls.Add(txt); Controls.Add(btn);
        y += 30;
        return txt;
    }

    private void Save()
    {
        try
        {
            _cfg.Killswitch.Persistent = _chkPersistent.Checked;
            _cfg.Killswitch.AllowLan = _chkLan.Checked;
            _cfg.Killswitch.DnsWhenDown = _cmbDns.SelectedItem?.ToString() ?? "svchost";
            _cfg.StopTunnelsOnVpnDown = _chkStopTunnels.Checked;
            _cfg.Openvpn.Binary = _txtBinary.Text.Trim();
            _cfg.Openvpn.Config = _txtOvpn.Text.Trim();
            _cfg.Killswitch.TunnelInterfaces = _txtPatterns.Text
                .Split('\n').Select(s => s.Trim().TrimEnd('\r')).Where(s => s.Length > 0).ToList();
            _cfg.Save();
            AllowedAppsForm.SendReload();
        }
        catch (Exception ex) { TrayAppContext.ShowError("Ошибка сохранения: " + ex.Message); }
    }
}
