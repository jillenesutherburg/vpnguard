namespace VpnGuard.Tray;

// ---------------------------------------------------------------------------
// Единое окно настроек с вкладками. Вся раскладка — на TableLayoutPanel /
// FlowLayoutPanel с AutoSize и Dock, без единой абсолютной координаты, поэтому
// корректно тянется при любом масштабе Windows (100–200%+) и на разных
// мониторах (PerMonitorV2). Размеры задаём в логических единицах, WinForms
// сам домножает на DPI.
// ---------------------------------------------------------------------------

public sealed class SettingsWindow : Form
{
    private readonly GuardConfig _cfg;

    // killswitch
    private CheckBox _chkPersistent = null!, _chkLan = null!, _chkStopTunnels = null!, _chkLockEndpoint = null!;
    private ComboBox _cmbDns = null!;
    private TextBox _txtBinary = null!, _txtOvpn = null!, _txtPatterns = null!;
    // apps
    private CheckBox _chkAllowlist = null!;
    private ListBox _lstApps = null!;
    // tunnels
    private DataGridView _grid = null!;
    private TabControl _tabs = null!;

    public void SelectTab(int index)
    {
        if (index >= 0 && index < _tabs.TabCount) _tabs.SelectedIndex = index;
    }

    public SettingsWindow()
    {
        _cfg = GuardConfig.Load();

        Text = "VPNGuard — настройки";
        StartPosition = FormStartPosition.CenterScreen;
        AutoScaleMode = AutoScaleMode.Dpi;      // масштабирование по DPI
        MinimumSize = new Size(560, 460);       // логические единицы
        Size = new Size(680, 560);
        Font = SystemFonts.MessageBoxFont!;     // системный шрифт → чёткий на HiDPI

        _tabs = new TabControl { Dock = DockStyle.Fill };
        _tabs.TabPages.Add(BuildKillswitchTab());
        _tabs.TabPages.Add(BuildAppsTab());
        _tabs.TabPages.Add(BuildTunnelsTab());

        var buttons = BuildButtonBar();

        // Кнопки — отдельной панелью, пристёгнутой к низу формы (Dock.Bottom),
        // а вкладки заполняют остаток (Dock.Fill). При таком раскладе кнопки
        // гарантированно поверх и кликабельны. ВАЖЕН порядок добавления:
        // при Dock последний добавленный control прижимается первым, поэтому
        // сначала добавляем Fill-контрол, затем Bottom-панель... нет — наоборот:
        // Dock.Fill должен добавляться ПОСЛЕ Dock.Bottom, иначе Fill заберёт всю
        // площадь. Поэтому добавляем панель кнопок первой, вкладки — второй.
        Controls.Add(buttons);   // Dock.Bottom — уйдёт вниз
        Controls.Add(_tabs);     // Dock.Fill — займёт остаток над кнопками
    }

    // ------------------------------------------------------------------ вкладка «Киллсвитч»

    private TabPage BuildKillswitchTab()
    {
        var page = new TabPage("Киллсвитч") { Padding = new Padding(10) };

        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,          // если не влезает — появится прокрутка, а не обрежется
        };

        _chkPersistent = AddCheck(flow, "«Железный» режим (persistent): фильтры переживают падение/остановку службы и перезагрузку", _cfg.Killswitch.Persistent);
        AddHint(flow, "Выключено = мягкий режим: при падении службы ОС сама снимает фильтры. Рекомендуется для обкатки.");

        _chkLan = AddCheck(flow, "Разрешить локальную сеть (allow_lan)", _cfg.Killswitch.AllowLan);
        AddHint(flow, "ВНИМАНИЕ: при включённом LAN трафик к 10/8, 172.16/12, 192.168/16 идёт мимо VPN всегда.");

        _chkStopTunnels = AddCheck(flow, "Останавливать туннели при падении VPN (stop_tunnels_on_vpn_down)", _cfg.StopTunnelsOnVpnDown ?? true);

        _chkLockEndpoint = AddCheck(flow, "Привязать разрешение VPN-сервера к openvpn.exe (lock_endpoint_to_app)", _cfg.Killswitch.LockEndpointToApp);
        AddHint(flow, "Выключено (реком.) = разрешение по IP:порт сервера, VPN коннектит при любой схеме запуска OpenVPN.");

        // DNS-режим строкой: подпись + комбо в одном FlowLayoutPanel
        var dnsRow = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0, 8, 0, 0) };
        dnsRow.Controls.Add(new Label { Text = "DNS, когда VPN отключён:", AutoSize = true, Anchor = AnchorStyles.Left, Padding = new Padding(0, 5, 6, 0) });
        _cmbDns = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 140 };
        _cmbDns.Items.AddRange(new object[] { "svchost", "off", "all" });
        _cmbDns.SelectedItem = _cfg.Killswitch.DnsWhenDown is "off" or "all" ? _cfg.Killswitch.DnsWhenDown : "svchost";
        dnsRow.Controls.Add(_cmbDns);
        flow.Controls.Add(dnsRow);
        AddHint(flow, "svchost — порт 53 только DNS-службе Windows. off — самый строгий (реконнект по кэшу IP). all — всем.");

        _txtBinary = AddPathRow(flow, "openvpn.exe:", _cfg.Openvpn.Binary);
        _txtOvpn = AddPathRow(flow, "Файл .ovpn:", _cfg.Openvpn.Config);

        flow.Controls.Add(new Label { Text = "Паттерны туннельных адаптеров (по одному на строку):", AutoSize = true, Margin = new Padding(0, 8, 0, 2) });
        _txtPatterns = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Text = string.Join(Environment.NewLine, _cfg.Killswitch.TunnelInterfaces),
            Width = 400,
            Height = 70,
        };
        flow.Controls.Add(_txtPatterns);

        page.Controls.Add(flow);
        return page;
    }

    // ------------------------------------------------------------------ вкладка «Приложения»

    private TabPage BuildAppsTab()
    {
        var page = new TabPage("Приложения") { Padding = new Padding(10) };

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            RowCount = 3,
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _chkAllowlist = new CheckBox
        {
            Text = "Режим белого списка: через туннель выходят ТОЛЬКО приложения из списка",
            Checked = _cfg.Killswitch.AppPolicy == "allowlist",
            AutoSize = true,
            Margin = new Padding(3, 3, 3, 8),
        };
        grid.Controls.Add(_chkAllowlist, 0, 0);
        grid.SetColumnSpan(_chkAllowlist, 2);

        _lstApps = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false, SelectionMode = SelectionMode.MultiExtended };
        foreach (var app in _cfg.Killswitch.AllowedApps) _lstApps.Items.Add(app);
        grid.Controls.Add(_lstApps, 0, 1);

        var appBtns = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Margin = new Padding(6, 0, 0, 0) };

        var btnAdd = new Button { Text = "Добавить…", AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        btnAdd.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog
            {
                Filter = "Программы (*.exe)|*.exe|Все файлы (*.*)|*.*",
                Multiselect = true,          // можно выбрать сразу несколько
                Title = "Выберите одно или несколько приложений",
            };
            if (dlg.ShowDialog() == DialogResult.OK)
                AddApps(dlg.FileNames);
        };

        var btnPaste = new Button { Text = "Вставить список…", AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        btnPaste.Click += (_, _) =>
        {
            using var d = new PathListDialog();
            if (d.ShowDialog() == DialogResult.OK)
                AddApps(d.Paths);
        };

        var btnDel = new Button { Text = "Удалить", AutoSize = true, Margin = new Padding(0, 0, 0, 4) };
        btnDel.Click += (_, _) =>
        {
            // удаляем все выделенные (список поддерживает множественный выбор)
            for (int i = _lstApps.SelectedIndices.Count - 1; i >= 0; i--)
                _lstApps.Items.RemoveAt(_lstApps.SelectedIndices[i]);
        };

        var btnClear = new Button { Text = "Очистить всё", AutoSize = true };
        btnClear.Click += (_, _) =>
        {
            if (_lstApps.Items.Count > 0 &&
                MessageBox.Show("Очистить весь список?", "VPNGuard",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                _lstApps.Items.Clear();
        };

        appBtns.Controls.Add(btnAdd);
        appBtns.Controls.Add(btnPaste);
        appBtns.Controls.Add(btnDel);
        appBtns.Controls.Add(btnClear);
        grid.Controls.Add(appBtns, 1, 1);

        var hint = new Label
        {
            Text = "DNS через туннель разрешён любому приложению (резолвит svchost) — это учтено службой.",
            AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(3, 6, 3, 0),
        };
        grid.Controls.Add(hint, 0, 2);
        grid.SetColumnSpan(hint, 2);

        page.Controls.Add(grid);
        return page;
    }

    /// <summary>Добавляет пути в список без дублей (без учёта регистра), сохраняя порядок.</summary>
    private void AddApps(IEnumerable<string> paths)
    {
        var existing = _lstApps.Items.Cast<string>()
            .Select(s => s.ToLowerInvariant()).ToHashSet();
        int added = 0, skipped = 0;
        foreach (var raw in paths)
        {
            var p = raw.Trim().Trim('"');
            if (p.Length == 0) continue;
            if (existing.Contains(p.ToLowerInvariant())) { skipped++; continue; }
            _lstApps.Items.Add(p);
            existing.Add(p.ToLowerInvariant());
            added++;
        }
        if (skipped > 0)
            MessageBox.Show($"Добавлено: {added}. Пропущено дублей: {skipped}.",
                "VPNGuard", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private TabPage BuildTunnelsTab()
    {
        var page = new TabPage("Туннели") { Padding = new Padding(10) };

        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3 };
        grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        _grid = new DataGridView
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,   // колонки тянутся под ширину
        };
        _grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText = "Автостарт", Name = "auto", FillWeight = 12 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Имя", Name = "name", FillWeight = 20 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Скрипт (.bat/.exe)", Name = "script", FillWeight = 40 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Пауза, с", Name = "rdelay", FillWeight = 12 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "Health-check host:port", Name = "check", FillWeight = 26 });
        foreach (var t in _cfg.Tunnels ?? new List<TunnelEntry>())
            _grid.Rows.Add(t.Autostart ?? true, t.Name, t.Script, t.RestartDelaySeconds, t.Check?.Target ?? "");
        grid.Controls.Add(_grid, 0, 0);

        var btns = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
        var btnAdd = new Button { Text = "Добавить скрипт…", AutoSize = true, Margin = new Padding(0, 0, 6, 0) };
        btnAdd.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { Filter = "Скрипты и программы (*.bat;*.cmd;*.exe)|*.bat;*.cmd;*.exe|Все файлы (*.*)|*.*" };
            if (dlg.ShowDialog() == DialogResult.OK)
                _grid.Rows.Add(true, Path.GetFileNameWithoutExtension(dlg.FileName), dlg.FileName, 5, "");
        };
        var btnDel = new Button { Text = "Удалить строку", AutoSize = true };
        btnDel.Click += (_, _) => { if (_grid.SelectedRows.Count > 0) _grid.Rows.Remove(_grid.SelectedRows[0]); };
        btns.Controls.Add(btnAdd);
        btns.Controls.Add(btnDel);
        grid.Controls.Add(btns, 0, 1);

        var hint = new Label
        {
            Text = "Health-check: TCP к проброшенному порту (напр. 127.0.0.1:1080); пусто — только контроль процесса. " +
                   "Пауза рестарта стартовая, при повторных падениях растёт ×2. Аргументы (args) — через «Открыть конфиг».",
            AutoSize = true, MaximumSize = new Size(600, 0), ForeColor = SystemColors.GrayText, Margin = new Padding(3, 6, 3, 0),
        };
        grid.Controls.Add(hint, 0, 2);

        page.Controls.Add(grid);
        return page;
    }

    // ------------------------------------------------------------------ кнопки

    private Panel BuildButtonBar()
    {
        // Внешняя панель прижата к низу и имеет достаточную высоту, чтобы
        // кнопки всегда были видны и кликабельны на любом DPI.
        var host = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 52,               // логические единицы; WinForms домножит на DPI
            Padding = new Padding(10, 8, 10, 8),
        };
        var bar = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.RightToLeft,
            WrapContents = false,
        };
        var btnCancel = new Button { Text = "Отмена", AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
        var btnSave = new Button { Text = "Сохранить и применить", AutoSize = true };
        btnCancel.Click += (_, _) => Close();
        btnSave.Click += (_, _) => { if (Save()) Close(); };
        bar.Controls.Add(btnCancel);
        bar.Controls.Add(btnSave);
        host.Controls.Add(bar);
        AcceptButton = btnSave;   // Enter
        CancelButton = btnCancel; // Esc
        return host;
    }

    // ------------------------------------------------------------------ хелперы раскладки

    private static CheckBox AddCheck(Control parent, string text, bool value)
    {
        var c = new CheckBox { Text = text, Checked = value, AutoSize = true, Margin = new Padding(0, 4, 0, 0), MaximumSize = new Size(600, 0) };
        parent.Controls.Add(c);
        return c;
    }

    private static void AddHint(Control parent, string text)
    {
        parent.Controls.Add(new Label
        {
            Text = text, AutoSize = true, ForeColor = SystemColors.GrayText,
            Margin = new Padding(20, 0, 0, 4), MaximumSize = new Size(580, 0),
        });
    }

    private static TextBox AddPathRow(FlowLayoutPanel parent, string label, string value)
    {
        var row = new FlowLayoutPanel { FlowDirection = FlowDirection.LeftToRight, AutoSize = true, WrapContents = false, Margin = new Padding(0, 6, 0, 0) };
        row.Controls.Add(new Label { Text = label, AutoSize = true, Padding = new Padding(0, 5, 6, 0), Width = 110, TextAlign = ContentAlignment.MiddleLeft });
        var txt = new TextBox { Text = value, Width = 360 };
        var btn = new Button { Text = "…", AutoSize = true, Margin = new Padding(4, 0, 0, 0) };
        btn.Click += (_, _) =>
        {
            using var dlg = new OpenFileDialog { FileName = txt.Text };
            if (dlg.ShowDialog() == DialogResult.OK) txt.Text = dlg.FileName;
        };
        row.Controls.Add(txt);
        row.Controls.Add(btn);
        parent.Controls.Add(row);
        return txt;
    }

    // ------------------------------------------------------------------ сохранение

    /// <summary>Сохраняет конфиг и шлёт reload. true — успех (окно можно закрыть).</summary>
    private bool Save()
    {
        try
        {
            _cfg.Killswitch.Persistent = _chkPersistent.Checked;
            _cfg.Killswitch.AllowLan = _chkLan.Checked;
            _cfg.Killswitch.LockEndpointToApp = _chkLockEndpoint.Checked;
            _cfg.Killswitch.DnsWhenDown = _cmbDns.SelectedItem?.ToString() ?? "svchost";
            _cfg.StopTunnelsOnVpnDown = _chkStopTunnels.Checked;
            _cfg.Openvpn.Binary = _txtBinary.Text.Trim();
            _cfg.Openvpn.Config = _txtOvpn.Text.Trim();
            _cfg.Killswitch.TunnelInterfaces = _txtPatterns.Text
                .Split('\n').Select(s => s.Trim().TrimEnd('\r')).Where(s => s.Length > 0).ToList();

            _cfg.Killswitch.AppPolicy = _chkAllowlist.Checked ? "allowlist" : "all";
            _cfg.Killswitch.AllowedApps = _lstApps.Items.Cast<string>().ToList();

            var oldByName = (_cfg.Tunnels ?? new List<TunnelEntry>())
                .GroupBy(t => t.Name).ToDictionary(g => g.Key, g => g.First());
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
                    RestartDelaySeconds = int.TryParse(row.Cells["rdelay"].Value?.ToString(), out var n) && n > 0 ? n : 5,
                    Check = string.IsNullOrEmpty(target) ? null : new CheckEntry
                    {
                        Type = "tcp", Target = target,
                        IntervalSeconds = old?.Check?.IntervalSeconds ?? 15,
                        TimeoutSeconds = old?.Check?.TimeoutSeconds ?? 3,
                        FailThreshold = old?.Check?.FailThreshold ?? 2,
                    },
                });
            }
            _cfg.Tunnels = list;

            _cfg.Save();

            var r = PipeClient.Send(new PipeRequest { Cmd = "reload" });
            if (!r.Ok)
            {
                MessageBox.Show("Конфиг сохранён на диск, но служба не подтвердила перезагрузку:\n" + r.Error +
                    "\n\nПроверьте, запущена ли служба VPNGuard.",
                    "VPNGuard", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return true; // на диск записано — окно закрываем
            }
            return true;
        }
        catch (Exception ex)
        {
            TrayAppContext.ShowError("Ошибка сохранения: " + ex.Message);
            return false; // не закрываем окно, чтобы пользователь не потерял правки
        }
    }
}

// ---------------------------------------------------------------------------
// Диалог массовой вставки: пользователь вставляет список путей (по одному на
// строку), получаем массив. Пути в кавычках и с лишними пробелами чистятся
// на стороне AddApps.
// ---------------------------------------------------------------------------

public sealed class PathListDialog : Form
{
    private readonly TextBox _text;

    /// <summary>Непустые строки, введённые пользователем.</summary>
    public string[] Paths { get; private set; } = Array.Empty<string>();

    public PathListDialog()
    {
        Text = "Вставить список путей";
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        MinimumSize = new Size(480, 360);
        Size = new Size(560, 420);
        Font = SystemFonts.MessageBoxFont!;

        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(10) };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        root.Controls.Add(new Label
        {
            Text = "Вставьте пути к .exe — по одному на строку. Кавычки и лишние пробелы уберутся автоматически.\n" +
                   @"Пример:  C:\Program Files\App\app.exe",
            AutoSize = true, Margin = new Padding(0, 0, 0, 6),
        }, 0, 0);

        _text = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            AcceptsReturn = true,
            Font = new Font(FontFamily.GenericMonospace, Font.Size),
        };
        root.Controls.Add(_text, 0, 1);

        var bar = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true, Margin = new Padding(0, 6, 0, 0) };
        var cancel = new Button { Text = "Отмена", AutoSize = true, DialogResult = DialogResult.Cancel, Margin = new Padding(6, 0, 0, 0) };
        var ok = new Button { Text = "Добавить", AutoSize = true, DialogResult = DialogResult.OK };
        ok.Click += (_, _) =>
        {
            Paths = _text.Text
                .Split('\n')
                .Select(s => s.Trim().TrimEnd('\r'))
                .Where(s => s.Length > 0)
                .ToArray();
        };
        bar.Controls.Add(cancel);
        bar.Controls.Add(ok);
        root.Controls.Add(bar, 0, 2);

        Controls.Add(root);
        AcceptButton = ok;
        CancelButton = cancel;
    }
}
