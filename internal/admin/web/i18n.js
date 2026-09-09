'use strict';

// Panel translations. The dictionary key is the English text as it appears
// in the markup (data-t elements) or in app.js (t('...') calls). English is
// the source language and needs no dictionary: t() returns the key as is.
//
// Keys for data-t-html elements are the element's innerHTML with whitespace
// collapsed; values may contain the same inline markup.
//
// Placeholders in JS strings look like {name} and are substituted by t().

const DICTIONARIES = {
  ru: {
    // --- header and tabs ---
    'Monitoring': 'Мониторинг',
    'Proxies': 'Прокси',
    'Lists': 'Листы',
    'Domains': 'Домены',
    'Certificate': 'Сертификат',
    'proxy': 'прокси',
    'Proxy address: this is what goes into the browser or application settings': 'Адрес прокси: его прописывают в настройках браузера или программы',
    'Language of the panel and the log': 'Язык панели и лога',
    'Toggle theme': 'Переключить тему',
    'The config was given with <code>-upstream</code> flags and there is nowhere to save it — the panel is read-only.': 'Конфиг задан флагами <code>-upstream</code>, сохранять его некуда — панель работает только на чтение.',

    // --- monitoring ---
    'Requests': 'Запросов',
    'Domains with traffic': 'Доменов с трафиком',
    'Uptime': 'Аптайм',
    'certificates cached': 'сертификатов в кэше',
    'goroutines': 'горутин',
    'heap': 'куча',
    'root CA valid until {date}': 'корневой CA до {date}',
    'Getting started': 'Как начать',
    '<b>Add proxies.</b> The <a href="#proxies">Proxies</a> tab: one at a time or as a list from your provider\'s price sheet.': '<b>Добавьте прокси.</b> Вкладка <a href="#proxies">Прокси</a>: по одному или списком из прайса поставщика.',
    '<b>Group them into a list.</b> The <a href="#lists">Lists</a> tab: a list is a set of proxies within which Fairway picks the best one itself.': '<b>Соберите их в лист.</b> Вкладка <a href="#lists">Листы</a>: лист — это набор прокси, внутри которого Fairway выбирает лучший сам.',
    '<b>Bind domains to the list.</b> The <a href="#rules">Domains</a> tab: a rule for an exact domain, for <code>*.suffix</code>, or a default list for everything.': '<b>Привяжите домены к листу.</b> Вкладка <a href="#rules">Домены</a>: правило на конкретный домен, на <code>*.суффикс</code> или лист по умолчанию для всех.',
    '<b>Send traffic.</b> Set the HTTP proxy in your browser or application to': '<b>Направьте трафик.</b> В настройках браузера или программы укажите HTTP-прокси',
    '. As soon as requests flow, domains and measurements will appear here.': '. Как только пойдут запросы, здесь появятся домены и замеры.',
    'No traffic yet — domains will appear as soon as requests go through the proxy.': 'Трафика ещё не было — домены появятся, как только через прокси пойдут запросы.',
    'Search domains': 'Поиск по домену',
    'Nothing matches the search.': 'Под поиск ничего не подошло.',
    'Pick a domain on the left to see which proxies serve it and how they behave.': 'Выберите домен слева, чтобы увидеть, какие прокси его обслуживают и как они себя ведут.',
    'Rule': 'Правило',
    'Proxies for this domain': 'Прокси домена',
    'sorted by cost: best on top': 'отсортированы по цене: лучший сверху',
    'Proxy': 'Прокси',
    'Status': 'Статус',
    'Now': 'Сейчас',
    'Connections right now': 'Соединений прямо сейчас',
    'Connect': 'Подключение',
    'Average time to establish a connection to the target': 'Среднее время установки соединения с целью',
    'First byte': 'Первый байт',
    'Average time to the first byte of the response': 'Среднее время до первого байта ответа',
    'Speed': 'Скорость',
    'Average download speed; measured on responses of 32 KB and above': 'Средняя скорость отдачи; считается по ответам от 32 КБ',
    'Errors': 'Ошибок',
    'Share of failed requests': 'Доля неудачных запросов',
    'Cost': 'Цена',
    'How many seconds a 64 KB response would take through this proxy. Lower is better — this is the number the proxy is picked by': 'Сколько секунд занял бы через этот прокси ответ в 64 КБ. Чем меньше, тем лучше — по этому числу и выбирается прокси',
    'Traffic share': 'Доля трафика',
    'Share of requests this proxy will get on the next pick, exploration included': 'Какую долю запросов этот прокси получит при следующем выборе, с учётом разведки',
    'A slow proxy stays in rotation with a small share. A banned one is switched off for this domain only and comes back by itself when the ban expires, or right away with “Unban”.': 'Медленный прокси остаётся в ротации с малой долей. Забаненный выключается только для этого домена и вернётся сам, когда бан истечёт, или сразу — кнопкой «Снять бан».',
    'Time to first byte': 'Время до первого байта',
    'over recent requests, one line per proxy': 'по последним запросам, отдельная линия на каждый прокси',
    'Live log': 'Живой лог',
    'last 40 requests, updates on its own': 'последние 40 запросов, обновляется сам',
    'Time': 'Время',
    'Size': 'Объём',
    'Total': 'Всего',
    '{shown} of {total}': '{shown} из {total}',
    '{n} · {banned} banned': '{n} · {banned} бан',
    '{n} requests, banned proxies: {banned}': '{n} запросов, забанено прокси: {banned}',
    '{n} requests': '{n} запросов',
    'rule': 'правило',
    'not found — traffic went direct': 'не найдено — трафик шёл напрямую',
    'Add rule': 'Добавить правило',
    'Edit rule': 'Изменить правило',
    'pattern': 'паттерн',
    'list': 'лист',
    'decrypt': 'расшифровка',
    'tunnel': 'туннель',
    'proxies at once': 'прокси разом',
    'connections per proxy': 'соединений на прокси',
    'unlimited': 'без ограничения',
    'ban': 'бан',
    'off': 'выключен',
    'No measurements for this domain yet': 'По этому домену ещё нет замеров',
    'banned until {time}': 'забанен до {time}',
    'Unban': 'Снять бан',
    'Ban lifted from {name}': 'Бан с {name} снят',
    'ok': 'ок',
    'degraded': 'деградирует',
    'probing': 'разведка',
    'untested': 'не проверен',
    'banned': 'забанен',
    'No requests yet': 'Запросов ещё не было',
    'error': 'ошибка',
    'captcha': 'капча',
    'a challenge page came instead of content: {vendor}': 'вместо содержимого пришла страница проверки: {vendor}',
    'not enough data — at least two successful requests are needed': 'мало данных — нужно хотя бы два успешных запроса',

    // --- units ---
    'ms': 'мс',
    'B': 'Б',
    'KB': 'КБ',
    'MB': 'МБ',
    'GB': 'ГБ',
    '/s': '/с',
    's': 'с',
    'min': 'мин',
    'h': 'ч',
    'd': 'д',

    // --- settings: common ---
    'status {code}': 'статус {code}',
    'Saved and applied': 'Сохранено и применено',
    'Nothing matches the search': 'Под поиск ничего не подошло',
    'Edit': 'Изменить',
    'Delete': 'Удалить',
    'Close': 'Закрыть',
    'Cancel': 'Отмена',
    'Save': 'Сохранить',
    'Re-read file': 'Перечитать файл',
    'File re-read and applied': 'Файл перечитан и применён',
    'from general settings': 'из общих настроек',

    // --- proxies ---
    'Add proxy': 'Добавить прокси',
    'Import list': 'Импорт списком',
    'Upstreams that carry the traffic. On their own they are not assigned anywhere: first they are grouped into a list, and the list is bound to a domain. File:': 'Апстримы, через которые уходит трафик. Сами по себе они никуда не назначаются: сначала собираются в лист, а лист уже привязывается к домену. Файл:',
    'Name': 'Имя',
    'Scheme': 'Схема',
    'IP or host': 'IP или хост',
    'Port': 'Порт',
    'Login': 'Логин',
    'Password': 'Пароль',
    'if required': 'если нужен',
    'Country': 'Страна',
    'Comment': 'Комментарий',
    'e.g. paid until December': 'например: куплен до декабря',
    'A whole connection string — <code>socks5://user:pass@1.2.3.4:1080</code> — can be pasted into “IP or host”, it will be split into fields.': 'Строку целиком — <code>socks5://user:pass@1.2.3.4:1080</code> — можно вставить в поле «IP или хост», она разложится по полям.',
    'One proxy per line. Understands <code>1.2.3.4:1080</code>, <code>1.2.3.4:1080:login:password</code>, <code>login:password@1.2.3.4:1080</code> and full URLs with a scheme. Empty lines and lines starting with <code>#</code> are skipped.': 'По одной строке на прокси. Понимает форматы <code>1.2.3.4:1080</code>, <code>1.2.3.4:1080:логин:пароль</code>, <code>логин:пароль@1.2.3.4:1080</code> и строку со схемой целиком. Пустые строки и строки, начинающиеся с <code>#</code>, пропускаются.',
    'Default scheme': 'Схема по умолчанию',
    'Name prefix': 'Префикс имён',
    'shared by the whole batch': 'общий для всей пачки',
    'Straight into list': 'Сразу в лист',
    'Import': 'Импортировать',
    'Configured proxies': 'Заведённые прокси',
    'Search: name, address, country, comment': 'Поиск: имя, адрес, страна, комментарий',
    'Selected': 'Отмечено',
    'list name': 'имя листа',
    'Add to list': 'В лист',
    'Remove from list': 'Убрать из листа',
    'Delete selected': 'Удалить отмеченные',
    'Clear selection': 'Снять отметки',
    'Select all shown': 'Отметить все показанные',
    'Address': 'Адрес',
    'In lists': 'В листах',
    'No proxies yet — add one or paste a list from a price sheet': 'Прокси пока нет — добавьте или вставьте список из прайса',
    'none': 'ни в одном',
    'The proxy gets no traffic until it is in a list': 'Прокси не получит трафика, пока не окажется в листе',
    'Delete proxy {name}? It will disappear from lists too.': 'Удалить прокси {name}? Из листов он тоже исчезнет.',
    'Proxy {name} deleted': 'Прокси {name} удалён',
    'Added to list {list}: {n}': 'Добавлено в лист {list}: {n}',
    'Removed from list {list}: {n}': 'Убрано из листа {list}: {n}',
    'Delete selected proxies ({n})? They will disappear from lists too.': 'Удалить отмеченные прокси ({n})? Из листов они тоже исчезнут.',
    'Proxies deleted: {n}': 'Удалено прокси: {n}',
    'Edit proxy: {name}': 'Изменить прокси: {name}',
    'Proxy {name} updated': 'Прокси {name} изменён',
    'Proxy {name} added': 'Прокси {name} добавлен',
    'Proxies imported: {n}': 'Импортировано прокси: {n}',
    'Added {n}': 'Добавлено {n}',
    ', duplicates skipped {n}': ', пропущено дубликатов {n}',
    ', not parsed {n}': ', не разобрано {n}',
    'line {n}': 'строка {n}',

    // --- lists ---
    'Create list': 'Создать лист',
    'A list is a set of proxies assigned to a domain. Within a list Fairway picks which proxy to use by itself and rebalances as measurements come in.': 'Лист — набор прокси, который назначается домену. Внутри листа Fairway сам выбирает, через какой прокси идти, и перестраивает выбор по замерам.',
    'List name': 'Имя листа',
    'The name can be changed: references in domain rules and the default list are updated automatically.': 'Имя можно менять: ссылки в правилах доменов и лист по умолчанию обновятся сами.',
    'Proxies in the list': 'Прокси в листе',
    'Search': 'Поиск',
    'Select all': 'Выбрать все',
    'Clear all': 'Снять все',
    'Save list': 'Сохранить лист',
    'Search: list name or a proxy in it': 'Поиск: имя листа или прокси в нём',
    'List': 'Лист',
    'Count': 'Штук',
    'Used by': 'Используется',
    'default': 'по умолчанию',
    'No lists yet — create the first one': 'Листов пока нет — создайте первый',
    'nowhere': 'нигде',
    'No rule references this list': 'Ни одно правило не ссылается на этот лист',
    ' It is used by: {where} — those rules will need another list.': ' Он используется: {where} — эти правила придётся переназначить.',
    'Delete list {name}?{warn}': 'Удалить лист {name}?{warn}',
    'List {name} deleted': 'Лист {name} удалён',
    'No proxies configured yet — add them on the “Proxies” tab.': 'Прокси ещё не заведены — добавьте их на вкладке «Прокси».',
    'selected {picked} of {total}': 'выбрано {picked} из {total}',
    ' · shown {n}': ' · показано {n}',
    'Edit list: {name}': 'Изменить лист: {name}',
    'List {name} saved': 'Лист {name} сохранён',
    'List {name} created': 'Лист {name} создан',

    // --- rules ---
    'General settings': 'Общие настройки',
    'A rule says which list serves a domain. Matching goes from specific to general: exact name → longest <code>*.suffix</code> → <code>*</code> → general settings.': 'Правило говорит, каким листом обслуживать домен. Подбор идёт от частного к общему: точное имя → самый длинный <code>*.суффикс</code> → <code>*</code> → общие настройки.',
    'Pattern': 'Паттерн',
    'example.com or *.example.com': 'example.com или *.example.com',
    'decrypt TLS': 'расшифровывать TLS',
    'Proxies at once': 'Прокси разом',
    'Connections per proxy': 'Соединений на прокси',
    '0 — as in general': '0 — как в общих',
    'Ban': 'Бан',
    'Save rule': 'Сохранить правило',
    'Zero in a limit means “take from general settings”, −1 means “unlimited”. Ban is a Go duration: <code>5m</code>, <code>1h30m</code>.': 'Ноль в лимитах означает «взять из общих настроек», −1 — «без ограничения». Бан — как в Go: <code>5m</code>, <code>1h30m</code>.',
    'Apply to domains without a rule of their own and fill in wherever a rule has a zero.': 'Действуют для доменов без своего правила и подставляются в правила там, где стоит ноль.',
    'Default list': 'Лист по умолчанию',
    'allow direct': 'разрешить напрямую',
    'Without “allow direct” a domain with no rule gets a 503 — which is better than silently leaving from your real IP.': 'Без «разрешить напрямую» домен без правила получит 503 — и это правильнее, чем молча уйти с вашего реального IP.',
    'Rules': 'Правила',
    'Search: pattern or list': 'Поиск: паттерн или лист',
    'How many different proxies from the list work on the domain at the same time': 'Сколько разных прокси листа работают на домен одновременно',
    'Connections': 'Соединений',
    'How many connections one proxy holds': 'Сколько соединений держит один прокси',
    'No rules yet — all domains follow the general settings': 'Правил пока нет — все домены идут по общим настройкам',
    'decrypt (from general)': 'расшифровка (из общих)',
    'tunnel (from general)': 'туннель (из общих)',
    'Delete rule {pattern}?': 'Удалить правило {pattern}?',
    'Rule {pattern} deleted': 'Правило {pattern} удалено',
    'Edit rule: {pattern}': 'Изменить правило: {pattern}',
    'Rule {pattern} saved': 'Правило {pattern} сохранено',
    '— do not add to a list —': '— не класть в лист —',
    '— not set —': '— не задан —',
    'General settings saved': 'Общие настройки сохранены',

    // --- certificate ---
    'Root certificate': 'Корневой сертификат',
    'Download .crt': 'Скачать .crt',
    'Needed only for MITM mode: for the browser not to complain about a substituted site certificate, the machine must trust our root. It is created on first start and is unique to every installation — it is not built into the binary, otherwise the private key would be shared by everyone.': 'Нужен только для режима MITM: чтобы браузер не ругался на подменённый сертификат сайта, машина должна доверять нашему корню. Он создаётся при первом запуске и у каждой установки свой — в бинарник не зашит, иначе приватный ключ был бы общим для всех.',
    'This certificate': 'Этот сертификат',
    'Issued to': 'Кому выдан',
    'Valid until': 'Действует до',
    'SHA-256 fingerprint': 'Отпечаток SHA-256',
    'SHA-1 fingerprint': 'Отпечаток SHA-1',
    'Store': 'Хранилище',
    'Install on this machine': 'Установка на эту машину',
    'Installed into the current user\'s store, no administrator rights needed.': 'Ставится в хранилище текущего пользователя, права администратора не нужны.',
    'Install into system': 'Установить в систему',
    'Remove from system': 'Удалить из системы',
    'After installation the machine will trust any certificate signed by this key. When fairway is no longer needed, remove the certificate with the same button.': 'После установки машина будет доверять любому сертификату, подписанному этим ключом. Когда fairway больше не нужен — удалите сертификат этой же кнопкой.',
    'Other machines on the network': 'Остальные машины сети',
    'Download the .crt and import it into “Trusted Root Certification Authorities”. In a domain this is rolled out by group policy. Firefox, Java and Python keep their own stores — add it there separately.': 'Скачайте .crt и импортируйте в «Доверенные корневые центры сертификации». В домене это раскатывается групповой политикой. Firefox, Java и Python держат своё хранилище — туда добавлять отдельно.',
    'installed in the system': 'установлен в системе',
    'not installed': 'не установлен',
    'Certificate installed': 'Сертификат установлен',
    'Remove the Fairway root certificate from the trusted ones on this machine?': 'Удалить корневой сертификат Fairway из доверенных на этой машине?',
    'Certificate removed from the system': 'Сертификат удалён из системы',
    'Language switched': 'Язык переключён',
  },
};

// The active language. Filled from the server (config) and cached locally
// so the page does not flash English on reload.
let lang = 'en';
try { lang = localStorage.getItem('fairway-lang') || 'en'; } catch (e) { /* private mode */ }

// Original English strings of translated elements, captured on first use.
const sources = new WeakMap();

function t(key, vars) {
  const dict = DICTIONARIES[lang];
  let out = (dict && dict[key]) || key;
  if (vars) {
    for (const [name, value] of Object.entries(vars)) out = out.split('{' + name + '}').join(String(value));
  }
  return out;
}

const collapse = (s) => s.replace(/\s+/g, ' ').trim();

// applyLanguage re-translates every marked element from its captured English
// source, so switching back and forth is lossless.
function applyLanguage(next) {
  if (next && DICTIONARIES[next] === undefined && next !== 'en') next = 'en';
  if (next) lang = next;
  try { localStorage.setItem('fairway-lang', lang); } catch (e) { /* private mode */ }
  document.documentElement.lang = lang;

  for (const el of document.querySelectorAll('[data-t]')) {
    if (!sources.has(el)) sources.set(el, collapse(el.textContent));
    el.textContent = t(sources.get(el));
  }
  for (const el of document.querySelectorAll('[data-t-html]')) {
    if (!sources.has(el)) sources.set(el, collapse(el.innerHTML));
    el.innerHTML = t(sources.get(el));
  }
  for (const el of document.querySelectorAll('[data-t-placeholder]')) {
    if (!el.dataset.tSource) el.dataset.tSource = el.placeholder;
    el.placeholder = t(el.dataset.tSource);
  }
  for (const el of document.querySelectorAll('[data-t-title]')) {
    if (!el.dataset.tTitleSource) el.dataset.tTitleSource = el.title;
    el.title = t(el.dataset.tTitleSource);
  }
  const select = document.getElementById('lang-select');
  if (select) select.value = lang;
}

// Locale for dates and numbers follows the language.
const locale = () => (lang === 'ru' ? 'ru-RU' : 'en-GB');

applyLanguage();
