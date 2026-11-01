# flow-unlock

MITM-прокси для OpenWrt, который снимает региональное ограничение Google
**Flow** на уровне сети — без VPN и без расширения браузера.

Перенос логики Chrome-расширения
[`flow-chrome-addon`](https://github.com/) (см. соседнюю папку) на роутер с
OpenWrt. Вместо перехвата ответа «изнутри» браузера через Chrome DevTools
Protocol здесь работает **MITM-прокси** на роутере, который перехватывает,
патчит и отдаёт целевой JavaScript-бандл Google Flow, а также ловит редирект на
`/unsupported-country` и возвращает клиента на `https://flow.google.com/`.

## Что делает

То же самое, что и расширение, но на уровне сети:

1. **Перехватывает** HTTPS-ответ бандла
   `https://www.gstatic.com/*AiSandboxAngularFrontend*/m=_b`.
2. **Патчит** его теми же двумя адаптивными стратегиями, что и `patch.js`:
   - `route-guard-v1` — заменяет региональную проверку
     `if(!X()) return … "/unsupported-country"` на `if(false)`;
   - `known-field-accessor-v1` — резервная стратегия по полям
     `_.uu(a, 31)` / `_.uu(a, 32)` (региональный флаг → `true`).
3. **Ловит редирект** на `/unsupported-country` и отвечает `302 → https://flow.google.com/`
   с защитой от циклов (cooldown, по умолчанию 15 секунд).
4. Ведёт состояние `enabled`, `handle_redirect`, `cooldown` через **UCI**, пишет
   статус последнего запуска в JSON-файл и логирует в syslog.

Стратегии и сообщения об ошибках (уникальность проверок, «country=…, age=…»)
перенесены из `patch.js` один в один.

### Отличие от расширения

| | Chrome-расширение | OpenWrt-версия |
|---|---|---|
| Перехват | CDP `Fetch.getResponseBody` внутри браузера | MITM (TLS-перехват) на роутере |
| Обнаружение редиректа | `webNavigation.onBeforeNavigate` | Перехват запроса `/unsupported-country` |
| Доверие | ничего не требуется | **нужно установить CA-сертификат роутера на клиенте** |
| Управление | иконка `ON/OFF` | `uci set … / service flow-local reload` |
| Статус | бейдж `ON/OFF/RUN/OK/ERR` | `flow-local -status`, `/tmp/flow-local/status.json` |

Главное следствие: чтобы прокси мог читать и менять тело HTTPS-ответа, клиент
должен доверять CA-сертификату роутера. Это стандартное требование любого MITM
(mitmproxy, Squid ssl_bump и т.п.).

## Структура

```
flow-openwrt/
├── main.go               # вход, флаги, сигналы, -status / -export-ca / -gen-ca
├── config.go             # конфиг + чтение UCI (/etc/config/flow-local)
├── patch.go              # порт patch.js (две стратегии + проверки уникальности)
├── patch_test.go
├── ca.go                 # генерация/загрузка CA и leaf-сертификатов
├── proxy.go              # goproxy (explicit) + transparent HTTP/HTTPS MITM
├── proxy_test.go
├── integration_test.go   # end-to-end: MITM-патч и редирект через прокси
├── build.sh              # кросс-компиляция под arm64/armv7/mips/mipsle/amd64
├── install.sh            # установка на роутер (binary + init.d + config + CA)
├── openwrt/
│   ├── Makefile          # пакет для OpenWrt SDK (справочный)
│   └── files/
│       ├── etc/init.d/flow-local    # procd init-скрипт
│       └── etc/config/flow-local    # UCI-конфиг по умолчанию
└── dist/                 # (после ./build.sh) готовые бинарники
```

## Требования

- **На машине сборки**: Go ≥ 1.24 (goproxy v1.9.2 требует 1.24+).
- **На роутере**: OpenWrt, бинарник собран без CGO (`CGO_ENABLED=0`), поэтому
  достаточно стандартного `libc` (musl/glibc без разницы). Для прозрачного
  режима нужен iptables (есть всегда).
- **На клиенте**: возможность установить CA-сертификат (Chrome/Firefox/ОС).

## Сборка

На машине с Go (например, macOS/Linux):

```sh
cd flow-openwrt
./build.sh
```

Появится `dist/` с бинарниками под распространённые архитектуры OpenWrt:

- `flow-local-linux-arm64` — ARMv8 (современные роутеры, Raspberry Pi 3+ и т.п.)
- `flow-local-linux-armv7` — ARMv7
- `flow-local-linux-mips` — MIPS big-endian (старые Atheros/MediaTek)
- `flow-local-linux-mipsle` — MIPS little-endian
- `flow-local-linux-amd64` — x86_64 (для теста в VM)

Определить архитектуру роутера: `uname -m` (или `cat /etc/openwrt_release`).

### Локальная проверка (без роутера)

```sh
go test ./...           # юнит + интеграционные тесты
go run . -status        # показать состояние
go run . -gen-ca /tmp/ca
go run . -export-ca /tmp/ca.crt
```

## Установка

1. Скопируйте на роутер нужный бинарник и папку `flow-openwrt`:

   ```sh
   scp dist/flow-local-linux-arm64 root@192.168.1.1:/tmp/
   scp -r . root@192.168.1.1:/tmp/flow-openwrt
   ```

2. На роутере запустите `install.sh`:

   ```sh
   # режим явного прокси (рекомендуемый для одного устройства)
   sh /tmp/flow-openwrt/install.sh /tmp/flow-local-linux-arm64

   # или прозрачный режим (перехват всего LAN 80/443 через iptables)
   sh /tmp/flow-openwrt/install.sh /tmp/flow-local-linux-arm64 --transparent
   ```

   Скрипт: ставит бинарник в `/usr/bin/flow-local`, init-скрипт в
   `/etc/init.d/flow-local`, UCI-конфиг в `/etc/config/flow-local`, генерирует
   уникальный CA в `/etc/flow-local/` и запускает сервис.

3. **Установите CA-сертификат на клиенте** — файл `/etc/flow-local/ca.crt`
   (скачайте, например, `scp root@192.168.1.1:/etc/flow-local/ca.crt .`):

   - **macOS**: открыть файл → добавить в «Связка ключей» → в свойствах
     сертификата поставить «Доверять всегда» (для SSL).
   - **Windows**: `certmgr.msc` → «Доверенные корневые центры сертификации» →
     импорт.
   - **Linux/Chrome**: Настройки → Конфиденциальность и безопасность →
     Безопасность → Управление сертификатами → Authorities → импорт.
   - **Android/iOS**: установить как доверенный корневой сертификат
     (на Android Chrome по умолчанию игнорирует пользовательские CA — нужен
     root или флаг `chrome://flags`/системный CA).

## Использование

### Режим явного прокси (по умолчанию, `transparent=0`)

На клиенте укажите прокси **роутер:8080** (в настройках ОС или браузера).
После этого любая вкладка `flow.google.com` обрабатывается автоматически —
бандл патчится, региональный редирект не срабатывает.

### Прозрачный режим (`transparent=1`)

Установка `--transparent` добавляет iptables-правила, перенаправляющие
80→3128 и 443→8443 с LAN-интерфейса (`br-lan`). Тогда прокси не нужно
прописывать на клиентах — достаточно доверять CA. Нетаргетный HTTPS трафик
прокси пропускает туннелем (raw TCP), таргетный — MITM.

### Управление (как «иконка» расширения)

```sh
# выключить автоматический режим
uci set flow-local.flow.enabled=0
uci commit flow-local
/etc/init.d/flow-local reload

# включить обратно
uci set flow-local.flow.enabled=1
uci commit flow-local
/etc/init.d/flow-local reload

# выключить обработку редиректа (только патч бандла, без MITM flow.google.com)
uci set flow-local.flow.handle_redirect=0
uci commit flow-local
/etc/init.d/flow-local reload
```

### Статус

```sh
flow-local -status
# enabled: true
# handle_redirect: true
# last run:
# {
#   "last_patched_url": "https://www.gstatic.com/.../m=_b",
#   "last_patch_strategy": "route-guard-v1",
#   "last_run_at": "2026-11-01T12:00:00Z"
# }
```

Логи сервиса: `logread -e flow-local`.

## Конфигурация (UCI)

Файл `/etc/config/flow-local`:

| Опция | По умолчанию | Описание |
|---|---|---|
| `enabled` | `1` | автообработка включена |
| `transparent` | `0` | прозрачный режим (слушатели 3128/8443) |
| `handle_redirect` | `1` | MITM `flow.google.com` и редирект с `/unsupported-country` |
| `listen_addr` | `0.0.0.0` | адрес слушателей |
| `proxy_port` | `8080` | порт явного прокси |
| `transparent_http_port` | `3128` | цель REDIRECT для 80 |
| `transparent_https_port` | `8443` | цель REDIRECT для 443 |
| `cooldown_seconds` | `15` | защита от цикла редиректов |
| `ca_cert` / `ca_key` | `/etc/flow-local/ca.{crt,key}` | CA для MITM |
| `status_file` | `/tmp/flow-local/status.json` | файл статуса |
| `verbose` | `0` | подробные логи |

После изменения любой опции — `uci commit flow-local` и
`/etc/init.d/flow-local reload` (порты/адреса меняются только при полном
рестарте `/etc/init.d/flow-local restart`).

## Как это устроено

- **Явный прокси** собран на библиотеке [`elazarl/goproxy`](https://github.com/elazarl/goproxy):
  MITM только для `www.gstatic.com` и `flow.google.com`, остальные CONNECT —
  туннель. Для целевого бандла вешается response-handler, для
  `/unsupported-country` — request-handler, отдающий 302.
- **Прозрачный HTTPS** — собственная реализация: принимаем TCP, вычитываем SNI
  из TLS ClientHello (не «съедая» байты), для таргетных хостов делаем TLS-руку с
  leaf-сертификатом от нашего CA (ALPN только `http/1.1`), для остальных — raw
  TCP-туннель.
- **Декомпрессия**: у исходящего запроса снимается `Accept-Encoding`, поэтому
  `http.Transport` сам договаривается о gzip и прозрачно распаковывает ответ —
  патчится уже распакованный JS (как `Fetch.getResponseBody` в расширении).
- **Сертификаты**: leaf-сертификаты подписываются на лету и кэшируются; CA
  генерируется один раз при установке (`flow-local -gen-ca`).

## Ограничения и безопасность

- MITM требует доверия к CA на каждом клиенте. **Не используйте** это на
  устройствах, где нельзя контролировать доверие, и не оставляйте CA-ключ
  доступным (`/etc/flow-local/ca.key` имеет права `0600`).
- MITM `flow.google.com` (при `handle_redirect=1`) расшифровывает весь трафик
  этого хоста, а не только `/unsupported-country`. Если это мешает работе Flow,
  отключите `handle_redirect` — останется только патч бандла.
- Прозрачный режим перенаправляет весь LAN-трафик 80/443 через прокси
  (нетаргетный — туннелем). Для точечного перехвата можно ограничить правила
  через ipset/dnsmasq до `www.gstatic.com` и `flow.google.com`.
- Это инструмент для локального тестирования, а не продуктовая система
  фильтрации трафика.
