# Стыковка C#-трея VpnSentinel с Go-службой VPNGuard

Твой pipe-протокол принят как есть. Go-служба слушает тот же пайп
`\\.\pipe\VpnSentinelService` (SYSTEM + Administrators), построчный JSON,
одно соединение — один запрос.

## Команды (совпадают с твоим SentinelWorker)

`ping`, `status`, `enable`, `disable`, `reload` — семантика та же.
Поле `arg` зарезервировано, пока не используется.

## Форма status

Совпадает с твоим `ServiceStatus`: `killswitchEnabled`, `vpnConnected`,
`adapterName`, `adapterIp`, `persistent`, `whitelistMode`,
`scripts[{name, running, restarts}]`. В `scripts` идут туннели из
Go-супервизора; `running=true` также когда туннель в состоянии
«проверка не проходит» (health-check ещё не добил до порога).

## Что поменять в трее

1. Конфиг теперь YAML: `C:\ProgramData\VPNGuard\config.yaml` (не
   config.json). Формы Settings/AllowedApps/Scripts должны читать/писать
   его. Поля см. в config.example (vpnguard init). После записи — слать
   `reload`, как ты и делал.
2. `--cleanup` у службы называется `vpnguard panic` (или `disable`).
3. Отличия семантики enable/disable: они НЕ пишут конфиг на диск (это
   делает трей перед reload), только меняют рантайм-состояние.
4. Всё остальное (иконки по статусу, меню, планировщик без UAC) — без
   изменений.

## Открытые вопросы к тебе

- В твоём Snapshot скриптов не было Detail/State строкой — если хочешь
  показывать «перезапуск через 20с» в тултипе, скажи, добавлю поле
  (расширение обратно совместимо).
- Имя пайпа оставил твоё (VpnSentinelService), чтобы трей завёлся без
  правок. Если переименовываем продукт целиком — меняем синхронно.
