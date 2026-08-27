# 🛡 AmneziaWG Config Analyzer
Лёгкий инструмент для анализа конфигураций AmneziaWG / WireGuard.
Проверяет параметры обфускации, устойчивость к DPI, валидность CPS-пакетов
и даёт конкретные рекомендации как усилить защиту.

Работает полностью в браузере — без серверов и передачи данных.

<p align="center">
  <img src="pic1.png" width="900">
</p>



---

🌐 Онлайн-тест

👉  [Открыть AmneziaWG Analyzer](https://pumbax.github.io/awg-analyzer/)

---

Что нового в v3.1

- ✅ **Поддержка AWG 3.1** — детект по `RandomTrailers` / `DisableCookies`, отдельный бейдж и цвет
- ✅ Разбор **всех параметров 3.x уровня устройства**: `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`, `RandomTrailers`, `DisableCookies` — формат («N» или «LO-HI», оба конца uint16), допустимость значений и смысл каждого
- ✅ Проверка `parse_bool`: `RandomTrailers`/`DisableCookies` принимают **только `on`/`off` и десятичное число** — на `true` импорт конфига в amneziawg-tools падает целиком
- ✅ Инвариант таймеров **`RekeyAfterTime` < `RejectAfterTime`** — иначе сессию отвергает раньше, чем она успевает сменить ключи, и туннель периодически встаёт
- 🔧 **Убрано ложное срабатывание на H1-H4 для 3.x**: при `HeaderProtectionKey` заголовок шифруется целиком вместе с типом пакета, поэтому `H1=1 H2=2 H3=3 H4=4` там **норма, а не сигнатура** — ровно так их оставляют официальный клиент Amnezia на 3.1 и генератор `awg2.sh` v0.7.27. Раньше анализатор выдавал на них CRIT и предлагал диапазоны, которые на 3.x — чистая цена (замер: 10 Мбит/с против 100+) без выигрыша в маскировке
- ✅ Версию 3.x поднимает **любой** ключ из набора 3.x, а не только `HeaderProtectionKey`: такой конфиг старый клиент не прочитает в принципе
- ✅ Детект «ключи 3.x есть, а `HeaderProtectionKey` нет» — заголовки не шифруются, обычно ключ выбросил импортёр клиента
- ✅ Проверка **запаса до 1500 байт** на 3.x: `MTU + 32 (WG) + S4 + ContentPaddingAddition + 28 (IP/UDP)`, плюс невидимый в конфиге хвост `RandomTrailers`
- ✅ Все **три** совпадения длин пакетов рукопожатия, а не одно: `S2 = S1+56` (Init/Response), `S3 = S1+84` (Init/Cookie), `S3 = S2+28` (Response/Cookie)
- ✅ Лимит `S2` на 3.x — общий `S_MAX = 1132` вместо 1188
- ✅ Актуальные требования к клиенту: 3.0 — amneziawg-tools v3.0.20260730+ и модуль v3.0.20260805+; 3.1 — v3.1.20260812+ на обеих сторонах; в приложении AmneziaVPN поддержка 3.1 с 5.0.1.5, прошивки роутеров её пока не умеют
- ✅ Апгрейд-путь 2.0 → 3.1 и 3.0 → 3.1 с готовыми командами

Что нового в v3

- ✅ **Поддержка AWG 3.0** — детект по `HeaderProtectionKey`, отдельный бейдж и цвет
- ✅ Проверка **S1-S4 ≥ 12** для header protection (`HeaderCipherNonceSize`) — при меньших значениях nonce ChaCha20 частично уходит в тело сообщения, шифрование заголовков молча слабеет без явной ошибки демона
- ✅ Разбор новых CPS-тегов **`<rc N>`** и **`<rd N>`** (случайные буквы/цифры), не только `<r>`/`<b>`
- ✅ Детект тегов **`<d>`/`<ds>`/`<dz>`** — парсятся в amneziawg-go 3.0.1, но не подключены к отправке пакетов (задел под AWG 4.0), использовать их пока нельзя
- ✅ Исправлен off-by-one: лимит тега `<r>/<rc>/<rd>` — **≤ 1000 байт включительно** (было ошибочно `<1000`)
- ✅ Поддержка диапазона `PersistentKeepalive = 22-30` (AWG 3.0 берёт случайное значение из диапазона на каждый handshake)
- ✅ Условный лимит S3/S4: для AWG 2.0 остаётся `S4 ≤ 32`, для AWG 3.0 действует общий `S_MAX = 1132` (1280 − 148, размер Init-пакета) — старое правило больше не даёт ложных срабатываний на 3.0-конфигах
- ✅ Апгрейд-путь 2.0 → 3.0 с готовыми командами
- ✅ Предупреждение про клиент: **AmneziaWG β**, а не основной AmneziaVPN — его импортёр (`importController.cpp`) переносит `Jc/Jmin/Jmax/S1-S4/H1-H4/I1-I5`, но выбрасывает `HeaderProtectionKey`; без него сервер не разбирает handshake initiation и подключение зависает без внятной ошибки

Что было в v2

- ✅ Глубокий разбор I1-I5 — проверка что CPS начинается с `<b 0x...>`, лимит `<r>` < 1000, детект устаревшего `<c>`
- ✅ Детект 7 протоколов CPS — TLS, DTLS, QUIC v1/v2, SIP, DNS, HTTP, STUN
- ✅ Уровни обфускации — Базовый / +I1 / +I1-I5 полный CPS chain
- ✅ Раздел "Что это за конфиг" — простым языком
- ✅ Раздел "Как усилить" — пошаговый upgrade path с готовыми командами
- ✅ Severity для fixes — CRIT / HIGH / MED / LOW
- ✅ H1-H4 квадранты uint32 — проверка непересечения диапазонов
- ✅ AWG 2.0 лимиты — S2 ≤ 1188, S4 ≤ 32, Jmax < MTU
- ✅ Endpoint = IP (не домен — deadlock на Keenetic)

---

Возможности

- 🔍 Автоопределение версии
  
  - WireGuard
  - AWG 1.0
  - AWG 1.5
  - AWG 2.0 (+ детект уровня обфускации)
  - AWG 3.0 (full CPS chain + HeaderProtection)
  - AWG 3.1 (+ RandomTrailers / DisableCookies)
  - 🧠 Анализ параметров
  
  - Junk packets ("Jc", "Jmin", "Jmax")
  - Handshake padding ("S1–S4")
  - Magic headers ("H1–H4") — в т.ч. диапазоны по квадрантам
  - CPS mimicry ("I1–I5") — разбор каждого тега
  - Параметры 3.x уровня устройства (HeaderProtectionKey, ContentPaddingAddition, таймеры, RandomTrailers, DisableCookies)
  - Endpoint, MTU, DNS, AllowedIPs, Keepalive (в т.ч. диапазон на 3.x)

- 🧬 Глубокий разбор CPS
  
  - Первый тег должен быть `<b 0x...>` (иначе handshake ломается)
  - `<r N>` строго ≤ 999 байт
  - Детект протокола по hex (TLS, QUIC, DTLS, SIP, DNS, HTTP, STUN)
  - Валидация первого байта под протокол
  - Устаревший тег `<c>` → ErrorCode 1000

- 📊 Оценка безопасности
  
  - Security Score
  - Stealth Score
  - DPI Detection Risk (LOW / MEDIUM / HIGH)
  - Camouflage — качество мимикрии под протокол

- 💡 Рекомендации в два уровня
  
  - 🔧 Что срочно исправить (по severity):
    - CRIT — ломает работу
    - HIGH — снижает защиту
    - MED — DNS leak, узкий Jmin/Jmax
    - LOW — оптимизация
  
  - 🚀 Как усилить защиту (пошаговый upgrade path):
    - Переход WireGuard → AWG
    - Обновление AWG 1.x → 2.0
    - Добавление I1 (базовый CPS)
    - Добавление I2-I5 (полный CPS chain)
    - Смена порта, MTU, H1-H4 диапазонов

---

Безопасность

Analyzer выполняет все вычисления локально.

- нет API-запросов
- нет отправки конфигураций
- нет внешних скриптов
- нет аналитики

Ваши PrivateKey и VPN-конфиги остаются в браузере.

---

Использование

1. Откройте анализатор
2. Вставьте ".conf" файл
3. Нажмите Analyze

или просто перетащите файл на страницу.

Ctrl + Enter → быстрый анализ

---

Для кого

- пользователи AmneziaWG
- администраторы WireGuard
- тестирование DPI обхода
- аудит VPN-конфигураций
- проверка валидности CPS перед использованием

---

Связанные проекты

- [awg2-toolza](https://github.com/pumbaX/awg-multi-script) — менеджер AmneziaWG 2.0 сервера с CPS-генератором
- [AmneziaWG Architect](https://architect.vai-rice.space/) — веб-генератор обфускации

---
## 💰 Поддержать

**Boosty:** https://boosty.to/awgtoolza/donate

| Сеть | Адрес |
|---|---|
| USDT TRC20 | `TN2rQAsGNHQr8wnneKRD14UMX629D2Ca5q` |
| USDT ERC20 | `0x721845234eeC44e0a9BaE78402965828C1bc6c57` |
| USDT TON | `UQCwj-RY2a4BH7sIDDeLb77XRaPDq0mb1FVwyC4UaOGbLMYy` |
| TON | `UQCdQtJO4CF0Lyeb93X2zdeWeAcDJ-ieBC3AaL7LIqWfMBg3` |

---

License

MIT
