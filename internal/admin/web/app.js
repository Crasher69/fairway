'use strict';

// Панель Fairway. Никакой сборки и зависимостей: файлы вшиты в бинарник,
// график рисуется руками в SVG — тащить ради него библиотеку незачем.

const state = {
  domain: null,
  stream: null,
  events: [],      // события выбранного домена, старые первыми
  maxEvents: 400,
  overview: null,
  domainRows: [],
};

const $ = (id) => document.getElementById(id);

// Строки поиска по спискам и таблицам. Объявлены здесь, а не в разделе
// настроек: список доменов на мониторинге тоже фильтруется.
const filters = { proxy: '', list: '', rule: '', members: '', domain: '' };

// --- тема ---

const THEME_KEY = 'fairway-theme';

function isDark() {
  const forced = document.documentElement.dataset.theme;
  if (forced) return forced === 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

$('theme-toggle').onclick = () => {
  const next = isDark() ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* приватный режим */ }
  renderChart();
  if (state.domain) refreshDomain().catch(() => {});
  // Страница плагина узнаёт тему из window.fairway.theme — собрать заново.
  if (currentView === 'plugin') {
    plugins.frameFor = null;
    renderPluginPage();
  }
};

// --- язык ---

// Пока запрос на смену языка в полёте, overview не должен откатить панель
// на прежний язык.
let langSwitching = false;

$('lang-select').onchange = (event) => {
  const next = event.target.value;
  langSwitching = true;
  applyLanguage(next);
  rerenderAll();
  send('PUT', 'api/language', { language: next })
    .then(() => toast(t('Language switched')))
    // Без файла конфига (режим -upstream) язык остаётся локальным
    // для панели — лог его не увидит, но и ошибки показывать незачем.
    .catch((err) => { if (!String(err.message).includes('501')) showConfigError(err); })
    .finally(() => { langSwitching = false; });
};

// rerenderAll перерисовывает всё, что собрано из строк в JS: разметка
// переводится applyLanguage, а таблицы и подписи — заново из данных.
function rerenderAll() {
  refreshDomains().catch(() => {});
  if (state.domain) {
    refreshDomain().catch(() => {});
    renderLog();
    renderChart();
  }
  if (state.overview) refreshOverview().catch(() => {});
  if (currentView && !['monitor', 'cert', 'access', 'plugins', 'plugin'].includes(currentView)) refreshSettings().catch(() => {});
  // Подписи формы и страница плагина — на новом языке.
  if (currentView === 'plugin') plugins.formFor = plugins.frameFor = null;
  refreshPlugins().catch(() => {});
  if (currentView === 'cert') refreshCert().catch(() => {});
}

// --- утилиты форматирования ---

const ms = (v) => (v === null || v === undefined ? '—' : (v < 10 ? v.toFixed(1) : Math.round(v)) + ' ' + t('ms'));

function bytes(n) {
  if (!n) return '—';
  const units = [t('B'), t('KB'), t('MB'), t('GB')];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
}

const speed = (v) => (!v ? '—' : bytes(v) + t('/s'));
const percent = (v) => (v ? (v * 100).toFixed(1) + '%' : '0%');

function duration(sec) {
  const s = Math.floor(sec);
  if (s >= 86400) return Math.floor(s / 86400) + ' ' + t('d') + ' ' + Math.floor((s % 86400) / 3600) + ' ' + t('h');
  if (s >= 3600) return Math.floor(s / 3600) + ' ' + t('h') + ' ' + Math.floor((s % 3600) / 60) + ' ' + t('min');
  if (s >= 60) return Math.floor(s / 60) + ' ' + t('min') + ' ' + (s % 60) + ' ' + t('s');
  return s + ' ' + t('s');
}

const clock = (iso) => new Date(iso).toLocaleTimeString(locale());

// Палитра серий. Цвет закрепляется за прокси в порядке первого появления и
// не меняется при перерисовке — иначе линия «прыгала» бы по цветам, когда
// один из прокси выпадает из выборки. Порядок оттенков подобран так, чтобы
// соседние различались и при дальтонизме.
const PALETTE = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#4a3aa7', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
};
const colorSlots = new Map();

function color(name) {
  if (!colorSlots.has(name)) colorSlots.set(name, colorSlots.size);
  const palette = isDark() ? PALETTE.dark : PALETTE.light;
  return palette[colorSlots.get(name) % palette.length];
}

async function api(path) {
  const resp = await fetch(path, { headers: { Accept: 'application/json' } });
  if (resp.status === 401) {
    // Сессия кончилась или её не было: показываем вход и глушим запрос,
    // иначе каждые две секунды на экран сыпались бы ошибки.
    showLogin();
    throw new Error('unauthorized');
  }
  if (!resp.ok) throw new Error(path + ': ' + resp.status);
  return resp.json();
}

// --- вход ---

let loginShown = false;
let loginMode = 'password';

// Что показать, зависит от того, чем закрыта панель. Пароля нет — просим
// токен: он есть в логе, и вставить его надо один раз, дальше он живёт
// в cookie. Пустая карточка без единого поля (так было в 0.2.0) выглядит
// как сломанная панель.
async function showLogin() {
  if (loginShown) return;
  loginShown = true;
  try {
    loginMode = (await (await fetch('api/auth')).json()).mode;
  } catch (e) {}
  const form = $('login-form');
  const byPassword = loginMode !== 'token';

  $('login-lead').textContent = byPassword
    ? t('The panel is protected by a password.')
    : t('The panel is protected by a token.');
  $('login-password-field').hidden = !byPassword;
  $('login-token-field').hidden = byPassword;
  // required снимается с невидимого поля: иначе браузер откажется
  // отправлять форму, ругаясь на то, чего не видно.
  form.password.required = byPassword;
  form.token.required = !byPassword;
  $('login-note').textContent = byPassword
    ? t('Or open the panel by the link with the token that fairway prints to the log on start.')
    : t('The token is in the log line “admin panel: http://…/?token=…”. Opening that link works too.');

  $('login').hidden = false;
  (byPassword ? form.password : form.token).focus();
}

$('login-form').onsubmit = async (event) => {
  event.preventDefault();
  const form = $('login-form');
  const error = $('login-error');
  error.hidden = true;

  if (loginMode === 'token') {
    // Токен проверяет сервер при выдаче страницы и кладёт в cookie —
    // тем же путём, что и ссылка из лога.
    window.location.search = '?token=' + encodeURIComponent(form.token.value.trim());
    return;
  }
  const resp = await fetch('api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: form.password.value }),
  });
  if (!resp.ok) {
    error.textContent = (await resp.text()).trim() || t('status {code}', { code: resp.status });
    error.hidden = false;
    return;
  }
  // Перезагрузка, а не продолжение с этой же страницы: половина панели
  // уже получила 401 и осталась пустой.
  window.location.reload();
};

$('logout').onclick = async () => {
  await fetch('api/logout', { method: 'POST' });
  window.location.reload();
};

// --- уведомления ---

let toastTimer = null;

function toast(text) {
  const box = $('toast');
  box.textContent = text;
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { box.hidden = true; }, 2200);
}

// --- шапка и плитки ---

async function refreshOverview() {
  const data = await api('api/overview');
  state.overview = data;
  $('version').textContent = data.version;
  $('requests').textContent = data.requests.toLocaleString(locale());
  $('proxies').textContent = data.proxies;
  $('uptime').textContent = duration(data.uptime_sec);
  $('certs').textContent = data.certs_cached;
  $('goroutines').textContent = data.goroutines;
  $('heap').textContent = data.heap_mb.toFixed(1) + ' ' + t('MB');
  $('proxy-addr').textContent = data.proxy_addr || '—';
  $('onboarding-addr').textContent = data.proxy_addr || '—';
  if (data.config_path) {
    document.querySelectorAll('.config-note').forEach((el) => { el.textContent = data.config_path; });
  }
  if (data.ca_subject) {
    const until = new Date(data.ca_expires).toLocaleDateString(locale());
    $('ca-info').textContent = t('root CA valid until {date}', { date: until });
  }
  $('config-readonly').hidden = data.editable;
  // Язык — из конфига: панель подстраивается под то, что применил сервер.
  if (data.language && data.language !== lang && !langSwitching) {
    applyLanguage(data.language);
    rerenderAll();
  }
  renderOnboarding();
}

// Подсказка «как начать» показывается, пока не пошёл трафик: без неё
// человек, впервые открывший панель, видит пустой список доменов и не
// понимает, что делать дальше.
function renderOnboarding() {
  const o = state.overview;
  if (!o) return;
  const hasTraffic = state.domainRows.length > 0;
  $('onboarding').hidden = hasTraffic;
  if (hasTraffic) return;

  const steps = [
    ['step-proxies', o.proxies > 0],
    ['step-lists', o.lists > 0],
    ['step-rules', o.domains > 0 || !!o.default_list],
    ['step-client', false],
  ];
  let nextMarked = false;
  for (const [id, done] of steps) {
    const li = $(id);
    li.classList.toggle('done', done);
    li.classList.toggle('next', !done && !nextMarked);
    if (!done) nextMarked = true;
  }
}

// --- список доменов ---

async function refreshDomains() {
  const rows = await api('api/domains');
  state.domainRows = rows;
  $('domains-hint').hidden = rows.length > 0;
  $('domains').textContent = rows.length;
  renderOnboarding();
  renderDomainList();
}

// renderDomainList рисует список с учётом поиска. Список перерисовывается
// каждые две секунды, поэтому строка поиска живёт в filters, а не в DOM.
// Выбранный домен показывается всегда: иначе, набрав поиск, человек терял
// бы из виду то, что сейчас открыто справа.
function renderDomainList() {
  const rows = state.domainRows;
  const list = $('domain-list');
  const shown = rows.filter((row) => row.domain === state.domain || matches(filters.domain, row.domain));
  $('domain-filter').hidden = rows.length === 0;
  $('domains-count').textContent = !rows.length ? ''
    : shown.length === rows.length ? `${rows.length}` : t('{shown} of {total}', { shown: shown.length, total: rows.length });
  $('domains-empty').hidden = !rows.length || shown.length > 0;

  list.replaceChildren(...shown.map((row) => {
    const li = document.createElement('li');
    li.className = row.domain === state.domain ? 'active' : '';

    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = row.domain;

    const count = document.createElement('span');
    count.className = 'count';
    count.textContent = row.banned ? t('{n} · {banned} banned', { n: row.requests, banned: row.banned }) : String(row.requests);
    count.title = row.banned
      ? t('{n} requests, banned proxies: {banned}', { n: row.requests, banned: row.banned })
      : t('{n} requests', { n: row.requests });
    if (row.banned) count.classList.add('status-ban');

    li.append(name, count);
    li.onclick = () => selectDomain(row.domain);
    return li;
  }));
}

// --- выбранный домен ---

function selectDomain(domain) {
  if (state.domain === domain) return;
  state.domain = domain;
  state.events = [];
  $('empty').hidden = true;
  $('detail').hidden = false;
  $('domain-title').textContent = domain;
  refreshDomains();
  refreshDomain();
  loadEvents().then(openStream);
}

function chip(label, value) {
  const el = document.createElement('span');
  el.className = 'chip';
  el.append(label + ': ');
  const b = document.createElement('b');
  b.textContent = value;
  el.append(b);
  return el;
}

function renderRule(rule) {
  const chips = [];
  const link = $('rule-edit-link');
  if (!rule.known) {
    chips.push(chip(t('rule'), t('not found — traffic went direct')));
    link.textContent = t('Add rule');
    link.dataset.action = 'add';
    link.href = '#rules';
    link.dataset.pattern = state.domain;
  } else {
    chips.push(
      chip(t('pattern'), rule.pattern),
      chip(t('list'), rule.list),
      chip('TLS', rule.mitm ? t('decrypt') : t('tunnel')),
      chip(t('proxies at once'), rule.max_parallel_proxies || t('unlimited')),
      chip(t('connections per proxy'), rule.max_conns_per_proxy || t('unlimited')),
      chip(t('ban'), humanDuration(rule.ban_duration)
        + (rule.max_ban_duration ? ' → ' + humanDuration(rule.max_ban_duration) : '')),
      chip(t('timeouts'), humanDuration(rule.connect_timeout) + ' / ' + humanDuration(rule.response_timeout)),
    );
    link.textContent = t('Edit rule');
    link.dataset.action = 'edit';
    link.dataset.pattern = rule.pattern === '' ? '' : rule.pattern;
  }
  $('rule').replaceChildren(...chips);
}

// humanDuration переводит "5m0s" в «5 мин»: строку Go человеку читать не надо.
function humanDuration(s) {
  if (!s) return '—';
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?$/.exec(s);
  if (!m) return s;
  const parts = [];
  if (m[1] && +m[1]) parts.push(+m[1] + ' ' + t('h'));
  if (m[2] && +m[2]) parts.push(+m[2] + ' ' + t('min'));
  if (m[3] && +m[3]) parts.push(+m[3] + ' ' + t('s'));
  return parts.join(' ') || t('off');
}

// Паттерн, который нужно подставить в форму правила, когда откроется
// вкладка «Домены»: у домена без правила ссылка ведёт сразу в форму.
let pendingRulePattern = null;

$('rule-edit-link').onclick = (event) => {
  // Переходим на вкладку с уже набранным поиском по нужному паттерну.
  event.preventDefault();
  const pattern = event.currentTarget.dataset.pattern || '';
  filters.rule = pattern;
  $('rule-filter').value = pattern;
  if (event.currentTarget.dataset.action === 'add') pendingRulePattern = pattern;
  window.location.hash = 'rules';
};

function badgeClass(proxy) {
  if (proxy.banned) return 'bad';
  switch (proxy.status) {
    case 'ok': return 'ok';
    case 'degraded': return 'warn';
    case 'probing': return 'info';
    case 'probation': return 'warn';
    default: return 'idle';
  }
}

function renderProxies(proxies) {
  const body = $('proxy-table').querySelector('tbody');
  if (!proxies.length) {
    body.replaceChildren(emptyRow(9, t('No measurements for this domain yet')));
    return;
  }
  body.replaceChildren(...proxies.map((p) => {
    const tr = document.createElement('tr');

    const name = document.createElement('td');
    name.className = 'name';
    name.textContent = p.name;
    const upstream = document.createElement('span');
    upstream.className = 'sub';
    upstream.textContent = p.upstream || '';
    name.append(upstream);

    const status = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + badgeClass(p);
    badge.textContent = p.banned
      ? t('banned until {time}', { time: new Date(p.banned_until).toLocaleTimeString(locale()) })
      : t(p.status);
    status.append(badge);
    if (p.banned) {
      if (p.ban_reason || p.ban_strikes > 1) {
        const why = document.createElement('span');
        why.className = 'sub';
        why.style.fontFamily = 'inherit';
        // Номер бана подряд: по нему видно, почему срок длиннее обычного.
        const strikes = p.ban_strikes > 1 ? t('ban #{n} in a row', { n: p.ban_strikes }) : '';
        why.textContent = [p.ban_reason, strikes].filter(Boolean).join(' · ');
        status.append(why);
      }
      const unban = button(t('Unban'), () => {
        $('config-error').hidden = true;
        send('POST', `api/domains/${encodeURIComponent(state.domain)}/unban/${encodeURIComponent(p.id)}`)
          .then((data) => { renderProxies(data.proxies); refreshDomains(); toast(t('Ban lifted from {name}', { name: p.name })); })
          .catch(showConfigError);
      }, 'ghost small unban');
      status.append(document.createElement('br'), unban);
    }

    const share = document.createElement('td');
    share.className = 'num';
    if (!p.banned && p.share > 0) {
      const box = document.createElement('div');
      box.className = 'share';
      const label = document.createElement('span');
      label.textContent = percent(p.share);
      const bar = document.createElement('div');
      bar.className = 'bar';
      const fill = document.createElement('i');
      fill.style.width = Math.max(2, p.share * 100) + '%';
      fill.style.background = color(p.name);
      bar.append(fill);
      box.append(label, bar);
      share.append(box);
    } else {
      share.textContent = '—';
      share.classList.add('dim');
    }

    tr.append(
      name,
      status,
      cell(p.active || '—', p.active ? '' : 'dim'),
      cell(p.samples ? ms(p.connect_ms) : '—'),
      cell(p.samples ? ms(p.ttfb_ms) : '—'),
      cell(speed(p.throughput)),
      cell(percent(p.error_rate), p.error_rate > 0.25 ? 'status-err' : ''),
      cell(p.samples ? p.cost.toFixed(3) + ' ' + t('s') : '—'),
      share,
    );
    return tr;
  }));
}

function cell(text, extra) {
  const td = document.createElement('td');
  td.className = 'num' + (extra ? ' ' + extra : '');
  td.textContent = text;
  return td;
}

async function refreshDomain() {
  if (!state.domain) return;
  const data = await api('api/domains/' + encodeURIComponent(state.domain));
  renderRule(data.rule);
  renderProxies(data.proxies);
}

// --- живой лог и график ---

async function loadEvents() {
  const list = await api('api/events?limit=200&domain=' + encodeURIComponent(state.domain));
  state.events = list.reverse(); // API отдаёт новые первыми, графику нужны старые
  renderLog();
  renderChart();
}

function pushEvent(event) {
  state.events.push(event);
  if (state.events.length > state.maxEvents) state.events.shift();
  renderLog();
  renderChart();
}

function renderLog() {
  const body = $('log-table').querySelector('tbody');
  const recent = state.events.slice(-40).reverse();
  if (!recent.length) {
    body.replaceChildren(emptyRow(7, t('No requests yet')));
    return;
  }
  body.replaceChildren(...recent.map((e) => {
    const tr = document.createElement('tr');
    const status = e.error ? t('error') : e.challenge ? e.status + ' ' + t('captcha') : (e.status || t('tunnel'));

    const proxy = document.createElement('td');
    proxy.className = 'name';
    proxy.textContent = e.proxy;

    const statusCell = cell(status, e.error || e.challenge || e.status >= 400 ? 'status-err' : '');
    if (e.error) statusCell.title = e.error;
    if (e.challenge) statusCell.title = t('a challenge page came instead of content: {vendor}', { vendor: e.challenge });

    const when = document.createElement('td');
    when.className = 'mono';
    when.textContent = clock(e.at);

    tr.append(
      when,
      proxy,
      statusCell,
      cell(e.reused ? 'keep-alive' : ms(e.connect_ms)),
      cell(ms(e.ttfb_ms)),
      cell(bytes(e.bytes)),
      cell(ms(e.total_ms)),
    );
    return tr;
  }));
}

// Линейный график: по горизонтали время, по вертикали TTFB, отдельная линия
// на каждый прокси. Точки запоминаются для подсказки при наведении.
const chart = { points: [], x: null, y: null, pad: { left: 60, right: 12, top: 12, bottom: 22 } };

function renderChart() {
  const svg = $('chart');
  const width = svg.clientWidth || 800;
  const height = svg.clientHeight || 200;
  const pad = chart.pad;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  const styles = getComputedStyle(document.documentElement);
  const lineColor = styles.getPropertyValue('--line').trim();
  const textColor = styles.getPropertyValue('--muted').trim();

  const points = state.events.filter((e) => !e.error && e.ttfb_ms > 0);
  chart.points = points;
  if (points.length < 2) {
    svg.replaceChildren(text(width / 2, height / 2, t('not enough data — at least two successful requests are needed'), 'middle', textColor));
    $('legend').replaceChildren();
    return;
  }

  // По горизонтали — порядковый номер запроса, а не время: трафик идёт
  // неровно, и при паузе в минуту все точки сплющились бы у правого края.
  const maxV = niceMax(Math.max(...points.map((e) => e.ttfb_ms)));
  const x = (i) => pad.left + (i / (points.length - 1)) * (width - pad.left - pad.right);
  const y = (v) => height - pad.bottom - (v / maxV) * (height - pad.top - pad.bottom);
  chart.x = x;
  chart.y = y;

  const parts = [];
  // Горизонтальная сетка с подписями.
  for (let i = 0; i <= 4; i++) {
    const value = (maxV / 4) * i;
    const yy = y(value);
    parts.push(line(pad.left, yy, width - pad.right, yy, lineColor));
    parts.push(text(pad.left - 8, yy + 4, Math.round(value) + ' ' + t('ms'), 'end', textColor));
  }
  // Подписи времени по краям: первый и последний запрос на графике.
  parts.push(text(pad.left, height - 6, clock(points[0].at), 'start', textColor));
  parts.push(text(width - pad.right, height - 6, clock(points[points.length - 1].at), 'end', textColor));

  const byProxy = new Map();
  points.forEach((e, i) => {
    if (!byProxy.has(e.proxy)) byProxy.set(e.proxy, []);
    byProxy.get(e.proxy).push([i, e]);
  });

  for (const [proxy, list] of byProxy) {
    if (list.length === 1) {
      // Одна точка линией не рисуется — ставим маркер, иначе прокси есть
      // в легенде, а на графике его нет.
      const [i, e] = list[0];
      const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      dot.setAttribute('cx', x(i).toFixed(1));
      dot.setAttribute('cy', y(e.ttfb_ms).toFixed(1));
      dot.setAttribute('r', '4');
      dot.setAttribute('fill', color(proxy));
      parts.push(dot);
      continue;
    }
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', list.map(([i, e], n) =>
      `${n ? 'L' : 'M'}${x(i).toFixed(1)},${y(e.ttfb_ms).toFixed(1)}`).join(' '));
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', color(proxy));
    path.setAttribute('stroke-width', '2');
    path.setAttribute('stroke-linejoin', 'round');
    path.setAttribute('stroke-linecap', 'round');
    parts.push(path);
  }
  // Вертикальная линия-курсор, показывается при наведении.
  const cursor = line(0, pad.top, 0, height - pad.bottom, textColor);
  cursor.id = 'chart-cursor';
  cursor.setAttribute('stroke-dasharray', '3 3');
  cursor.setAttribute('visibility', 'hidden');
  parts.push(cursor);
  svg.replaceChildren(...parts);

  $('legend').replaceChildren(...[...byProxy.keys()].map((proxy) => {
    const span = document.createElement('span');
    const swatch = document.createElement('i');
    swatch.style.background = color(proxy);
    span.append(swatch, proxy);
    return span;
  }));
}

// niceMax округляет потолок оси вверх до «круглого» значения, чтобы подписи
// сетки не выглядели как 137 мс, 274 мс, 411 мс.
function niceMax(v) {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  const m = v / exp;
  const nice = m <= 1 ? 1 : m <= 2 ? 2 : m <= 4 ? 4 : m <= 5 ? 5 : 10;
  return nice * exp;
}

function line(x1, y1, x2, y2, stroke) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  el.setAttribute('x1', x1); el.setAttribute('y1', y1);
  el.setAttribute('x2', x2); el.setAttribute('y2', y2);
  el.setAttribute('stroke', stroke);
  return el;
}

function text(x, y, value, anchor, fill) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  el.setAttribute('x', x); el.setAttribute('y', y);
  el.setAttribute('fill', fill);
  el.setAttribute('font-size', '11');
  el.setAttribute('text-anchor', anchor);
  el.textContent = value;
  return el;
}

// Подсказка при наведении: ближайший по времени запрос каждого прокси.
$('chart-wrap').addEventListener('mousemove', (event) => {
  if (!chart.x || chart.points.length < 2) return;
  const svg = $('chart');
  const rect = svg.getBoundingClientRect();
  const px = event.clientX - rect.left;
  let best = null;
  chart.points.forEach((e, i) => {
    const d = Math.abs(chart.x(i) - px);
    if (!best || d < best.d) best = { d, e, i };
  });
  if (!best || best.d > 40) { hideTip(); return; }

  // В подсказке — ближайший запрос и по одному последнему замеру остальных
  // прокси, чтобы было с чем сравнить.
  const nearby = new Map([[best.e.proxy, best.e]]);
  for (let i = best.i - 1; i >= 0 && nearby.size < 8; i--) {
    const e = chart.points[i];
    if (!nearby.has(e.proxy)) nearby.set(e.proxy, e);
  }
  const tip = $('chart-tip');
  const rows = [...nearby.values()].map((e) => {
    const row = document.createElement('div');
    row.className = 'row';
    const swatch = document.createElement('i');
    swatch.style.cssText = `width:10px;height:3px;border-radius:2px;background:${color(e.proxy)}`;
    const b = document.createElement('b');
    b.textContent = ms(e.ttfb_ms);
    row.append(swatch, e.proxy, b);
    return row;
  });
  const when = document.createElement('div');
  when.className = 't';
  when.textContent = clock(best.e.at) + (best.e.status ? ` · ${best.e.status}` : '');
  tip.replaceChildren(when, ...rows);
  tip.hidden = false;
  const cx = chart.x(best.i);
  const cursor = $('chart-cursor');
  if (cursor) {
    cursor.setAttribute('x1', cx);
    cursor.setAttribute('x2', cx);
    cursor.setAttribute('visibility', 'visible');
  }
  const left = cx + 14 + tip.offsetWidth > rect.width ? cx - tip.offsetWidth - 14 : cx + 14;
  tip.style.left = left + 'px';
  tip.style.top = Math.max(0, event.clientY - rect.top - tip.offsetHeight / 2) + 'px';
});

$('chart-wrap').addEventListener('mouseleave', hideTip);

function hideTip() {
  $('chart-tip').hidden = true;
  const cursor = $('chart-cursor');
  if (cursor) cursor.setAttribute('visibility', 'hidden');
}

// --- поток событий ---

function openStream() {
  if (state.stream) state.stream.close();
  // EventSource сам переподключается при обрыве — отдельная логика не нужна.
  state.stream = new EventSource('api/stream?domain=' + encodeURIComponent(state.domain));
  state.stream.onmessage = (msg) => pushEvent(JSON.parse(msg.data));
}

// --- доступ в панель ---

async function refreshAccess() {
  const cfg = await api('api/config');
  $('password-state').textContent = cfg.password_set ? t('password is set') : t('no password, token only');
  $('password-clear').hidden = !cfg.password_set;
  fillProxyAuth(cfg.proxy_auth || {});
}

// --- вход на прокси ---

function fillProxyAuth(auth) {
  const form = $('proxy-auth-form');
  const users = auth.users || [];
  form.enabled.checked = !!auth.enabled;
  form.users.value = users.map((u) => u.login + ':' + u.password).join('\n');
  $('proxy-auth-state').textContent = auth.enabled
    ? t('on, users: {n}', { n: users.length })
    : t('off, the proxy is open');
}

$('proxy-auth-form').onsubmit = (event) => {
  event.preventDefault();
  const form = $('proxy-auth-form');
  const users = [];
  for (const raw of form.users.value.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    // Делим по первому двоеточию: в логине его быть не может, в пароле — может.
    const at = line.indexOf(':');
    if (at < 0) {
      showConfigError(new Error(t('line “{line}”: expected login:password', { line })));
      return;
    }
    users.push({ login: line.slice(0, at), password: line.slice(at + 1) });
  }
  // Форму перечитываем только после успешного сохранения: при ошибке
  // введённое должно остаться на месте, чтобы его можно было поправить.
  edit(async () => {
    await send('PUT', 'api/proxy-auth', { enabled: form.enabled.checked, users });
    await refreshAccess();
  }, t('Proxy authorization saved'));
};

$('password-form').onsubmit = (event) => {
  event.preventDefault();
  const form = $('password-form');
  if (form.password.value !== form.repeat.value) {
    showConfigError(new Error(t('passwords do not match')));
    return;
  }
  edit(() => send('PUT', 'api/password', { password: form.password.value }), t('Password saved')).then(() => {
    form.reset();
    refreshAccess().catch(() => {});
  });
};

$('password-clear').onclick = () => {
  if (!confirm(t('Remove the password? The panel will then be open by token only.'))) return;
  edit(() => send('PUT', 'api/password', { password: '' }), t('Password removed')).then(() => {
    $('password-form').reset();
    refreshAccess().catch(() => {});
  });
};

// --- плагины ---

// Плагины живут в своём разделе: меню в шапке со страницами включённых
// плагинов, страница «Плагины» со всеми установленными и страница каждого
// плагина. Страница плагина собирается панелью сама (статус, настройки по
// схеме из манифеста, права, лог), а если в пакете есть ui/index.html —
// сверху показывается и она, в изолированном iframe.

const plugins = {
  list: [],        // ответ api/plugins
  dir: '',
  current: null,   // имя открытого плагина
  frameFor: null,  // чья страница сейчас в iframe
  formFor: null,   // для чьих настроек нарисована форма
};

// Что значит каждое право — человеческими словами. Их видят при включении
// плагина, поэтому формулировки про то, что плагин сможет сделать.
function permissionText(perm, p) {
  const hosts = p.http_hosts;
  switch (perm) {
    case 'config.read': return t('read proxies, lists and domains (with proxy passwords)');
    case 'config.write': return t('change proxies, lists and domains');
    case 'events': return t('receive events: config applied, proxy banned');
    case 'schedule': return t('run on a timer');
    case 'http.fetch': return t('make HTTP requests to: {hosts}', { hosts: (hosts || []).join(', ') || '—' });
    case 'requests': return hooksText(p.hooks || {});
    default: return perm;
  }
}

// hooksText — какие запросы видит и меняет плагин вида hook.
function hooksText(h) {
  const domains = (h.domains || []).map((d) => (d === '*' ? t('all sites') : d)).join(', ') || '—';
  let text;
  if (h.request && h.response) text = t('see and change requests and responses to: {domains}', { domains });
  else if (h.response) text = t('see and change responses from: {domains}', { domains });
  else text = t('see and change requests to: {domains}', { domains });
  return h.body ? text + ' ' + t('(including bodies)') : text;
}

const PLUGIN_STATES = {
  running: ['ok', 'running'],
  starting: ['info', 'starting'],
  failed: ['bad', 'failed'],
  needs_permissions: ['warn', 'needs permissions'],
  disabled: ['idle', 'off'],
  invalid: ['bad', 'broken package'],
  missing: ['warn', 'not installed'],
};

function pluginBadge(p) {
  const [cls, label] = PLUGIN_STATES[p.state] || ['idle', p.state];
  const el = document.createElement('span');
  el.className = 'badge ' + cls;
  el.textContent = t(label);
  return el;
}

// localized — title и description плагина или поля настроек на языке
// панели: из i18n[lang], а чего там нет — как написано в манифесте.
const localized = (o) => ({ ...o, ...((o.i18n && o.i18n[lang]) || {}) });
const pluginTitle = (p) => localized(p).title || p.name;

async function refreshPlugins() {
  const resp = await api('api/plugins');
  plugins.list = resp.plugins || [];
  plugins.dir = resp.dir || '';
  renderPluginsMenu();
  if (currentView === 'plugins') renderPluginsTable();
  if (currentView === 'plugin') renderPluginPage();
}

// --- меню в шапке ---

function renderPluginsMenu() {
  const items = $('plugins-menu-items');
  items.textContent = '';
  const enabled = plugins.list.filter((p) => p.enabled);
  for (const p of enabled) {
    const a = document.createElement('a');
    a.href = '#plugin/' + encodeURIComponent(p.name);
    a.setAttribute('role', 'menuitem');
    if (currentView === 'plugin' && plugins.current === p.name) a.className = 'active';
    const dot = document.createElement('i');
    const cls = (PLUGIN_STATES[p.state] || ['idle'])[0];
    dot.className = 'dot' + (cls === 'ok' || cls === 'bad' || cls === 'warn' ? ' ' + cls : '');
    const name = document.createElement('span');
    name.textContent = pluginTitle(p);
    a.append(dot, name);
    items.append(a);
  }
  $('plugins-menu-empty').hidden = enabled.length > 0;
}

function setPluginsMenu(open) {
  const tab = $('plugins-tab');
  const menu = $('plugins-menu-list');
  menu.hidden = !open;
  tab.setAttribute('aria-expanded', String(open));
  if (!open) return;
  const rect = tab.getBoundingClientRect();
  menu.style.top = rect.bottom - 4 + 'px';
  menu.style.left = Math.max(8, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 8)) + 'px';
}

$('plugins-tab').onclick = (event) => {
  event.stopPropagation();
  setPluginsMenu($('plugins-menu-list').hidden);
};
$('plugins-menu-list').onclick = () => setPluginsMenu(false);
document.addEventListener('click', (event) => {
  if (!$('plugins-menu').contains(event.target)) setPluginsMenu(false);
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') setPluginsMenu(false);
});
window.addEventListener('resize', () => setPluginsMenu(false));
window.addEventListener('scroll', () => setPluginsMenu(false), { passive: true });

// --- включение и права ---

// askPermissions показывает, что плагин сможет делать, и спрашивает
// согласия. Права выдаются ровно те, что просит манифест.
function askPermissions(p) {
  const perms = p.permissions || [];
  if (!perms.length) return true;
  const lines = perms.map((perm) => '• ' + permissionText(perm, p));
  return window.confirm(t('Plugin “{name}” will be able to:', { name: pluginTitle(p) }) + '\n\n' + lines.join('\n'));
}

function savePlugin(name, body, done) {
  $('config-error').hidden = true;
  return send('PUT', 'api/plugins/' + encodeURIComponent(name), body)
    .then((resp) => {
      plugins.list = resp.plugins || [];
      renderPluginsMenu();
      if (currentView === 'plugins') renderPluginsTable();
      if (currentView === 'plugin') renderPluginPage();
      toast(done || t('Saved and applied'));
    })
    .catch(showConfigError);
}

function enablePlugin(p) {
  if (!askPermissions(p)) return;
  savePlugin(p.name, { enabled: true, granted: p.permissions || [] }, t('Plugin turned on'));
}

function disablePlugin(p) {
  savePlugin(p.name, { enabled: false }, t('Plugin turned off'));
}

// pluginAction — главная кнопка плагина: включить, выдать недостающие
// права или выключить.
function pluginAction(p) {
  if (p.state === 'invalid' || p.state === 'missing') return null;
  if (!p.enabled) return [t('Turn on'), () => enablePlugin(p), 'primary'];
  if (p.state === 'needs_permissions') return [t('Grant permissions'), () => enablePlugin(p), 'primary'];
  return [t('Turn off'), () => disablePlugin(p), 'ghost'];
}

// --- страница «Плагины» ---

function renderPluginsTable() {
  const body = $('cfg-plugins').querySelector('tbody');
  body.textContent = '';
  $('plugins-dir').textContent = plugins.dir ? t('folder: {dir}', { dir: plugins.dir }) : '';
  if (!plugins.list.length) {
    body.append(emptyRow(5, t('No plugins installed yet.')));
    return;
  }
  for (const p of plugins.list) {
    const tr = document.createElement('tr');

    const name = document.createElement('td');
    const title = document.createElement('div');
    title.className = 'plugin-name';
    const link = document.createElement('a');
    link.href = '#plugin/' + encodeURIComponent(p.name);
    link.textContent = pluginTitle(p);
    title.append(link);
    const id = document.createElement('div');
    id.className = 'plugin-id';
    id.textContent = p.name;
    name.append(title, id);
    const { description } = localized(p);
    if (description) {
      const desc = document.createElement('div');
      desc.className = 'plugin-desc';
      desc.textContent = description;
      name.append(desc);
    }

    const state = document.createElement('td');
    state.append(pluginBadge(p));
    if (p.error) {
      const err = document.createElement('div');
      err.className = 'hint status-err';
      err.textContent = p.error;
      state.append(err);
    }

    const perms = document.createElement('td');
    const permList = document.createElement('div');
    permList.className = 'perm-list';
    const missing = new Set(p.missing_permissions || []);
    for (const perm of p.permissions || []) {
      const code = document.createElement('code');
      code.textContent = perm;
      code.title = permissionText(perm, p);
      if (p.enabled && missing.has(perm)) code.className = 'missing';
      permList.append(code);
    }
    if (!(p.permissions || []).length) permList.textContent = '—';
    perms.append(permList);

    const buttons = [button(t('Open'), () => { window.location.hash = 'plugin/' + encodeURIComponent(p.name); }, 'ghost')];
    const action = pluginAction(p);
    if (action) buttons.unshift(button(...action));

    tr.append(name, textCell(p.version), state, perms, actionCell(...buttons));
    body.append(tr);
  }
}

$('plugins-rescan').onclick = () => {
  // Перечитать конфиг — значит заново свериться с каталогом плагинов:
  // менеджер обходит его при каждом применении конфига.
  send('POST', 'api/config/reload')
    .then(() => new Promise((resolve) => setTimeout(resolve, 300)))
    .then(refreshPlugins)
    .then(() => toast(t('Plugins folder rescanned')))
    .catch(showConfigError);
};

// --- страница плагина ---

function currentPlugin() {
  return plugins.list.find((p) => p.name === plugins.current) || null;
}

function openPluginPage(name) {
  plugins.current = name;
  plugins.formFor = null;
  plugins.frameFor = null;
  $('plugin-frame').srcdoc = '';
  refreshPlugins().then(refreshPluginLog).catch(showConfigError);
}

function renderPluginPage() {
  const p = currentPlugin();
  if (!p) {
    $('plugin-title').textContent = plugins.current || '—';
    $('plugin-version').textContent = '';
    $('plugin-state').textContent = '';
    $('plugin-description').textContent = t('This plugin is not installed.');
    $('plugin-toggle').hidden = true;
    return;
  }
  $('plugin-title').textContent = pluginTitle(p);
  $('plugin-version').textContent = p.version ? 'v' + p.version : '';
  $('plugin-state').replaceChildren(pluginBadge(p));
  $('plugin-description').textContent = localized(p).description || '';

  const toggle = $('plugin-toggle');
  const action = pluginAction(p);
  toggle.hidden = !action;
  if (action) {
    toggle.textContent = action[0];
    toggle.onclick = action[1];
    toggle.className = action[2];
  }

  const error = $('plugin-error');
  error.hidden = !p.error;
  error.textContent = p.error || '';

  const facts = [];
  if (p.last_tick) facts.push(t('last run by timer') + ' <b>' + escapeHTML(clock(p.last_tick)) + '</b>');
  if (p.last_error) facts.push(t('last error') + ' <b>' + escapeHTML(clock(p.last_error_at)) + '</b>: ' + escapeHTML(p.last_error));
  $('plugin-facts').innerHTML = facts.join(' &nbsp;·&nbsp; ');
  $('plugin-facts').hidden = !facts.length;

  renderPluginPerms(p);
  if (plugins.formFor !== p.name) {
    renderPluginSettings(p);
    plugins.formFor = p.name;
  }
  renderPluginFrame(p);
}

function escapeHTML(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

function renderPluginPerms(p) {
  const list = $('plugin-perms');
  list.textContent = '';
  const missing = new Set(p.missing_permissions || []);
  for (const perm of p.permissions || []) {
    const li = document.createElement('li');
    const code = document.createElement('code');
    code.textContent = perm;
    const text = document.createElement('span');
    text.textContent = permissionText(perm, p);
    li.append(code, text);
    if (p.enabled && missing.has(perm)) {
      const note = document.createElement('span');
      note.className = 'missing';
      note.textContent = t('not granted');
      li.append(note);
    }
    list.append(li);
  }
  if (!(p.permissions || []).length) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = t('The plugin asks for no permissions.');
    list.append(li);
  }
}

// --- настройки по схеме ---

// Форма строится по settings_schema из манифеста: строки, числа, флаги и
// выбор из списка. Всё, что сложнее, правится как JSON — поле для поля,
// а без схемы — все настройки целиком.
function renderPluginSettings(p) {
  const box = $('plugin-settings-fields');
  box.textContent = '';
  const values = p.settings && typeof p.settings === 'object' ? p.settings : {};
  const schema = p.settings_schema;
  const props = schema && schema.type === 'object' && schema.properties;

  if (!props || !Object.keys(props).length) {
    const field = document.createElement('label');
    field.className = 'field';
    const caption = document.createElement('span');
    caption.textContent = t('Settings (JSON)');
    const area = document.createElement('textarea');
    area.name = '__all';
    area.spellcheck = false;
    area.value = JSON.stringify(values, null, 2);
    field.append(caption, area);
    const hint = document.createElement('p');
    hint.className = 'hint';
    hint.textContent = t('The plugin does not describe its settings, so they are edited as JSON.');
    box.append(field, hint);
    return;
  }

  for (const [key, raw] of Object.entries(props)) {
    const prop = localized(raw);
    const value = key in values ? values[key] : prop.default;
    const caption = document.createElement('span');
    caption.textContent = prop.title || key;
    let field;
    if (prop.type === 'boolean') {
      field = document.createElement('label');
      field.className = 'toggle';
      const input = document.createElement('input');
      input.type = 'checkbox';
      input.name = key;
      input.dataset.kind = 'boolean';
      input.checked = !!value;
      field.append(input, caption);
    } else {
      field = document.createElement('label');
      field.className = 'field';
      let input;
      if (Array.isArray(prop.enum)) {
        input = document.createElement('select');
        for (const option of prop.enum) {
          const el = document.createElement('option');
          el.value = JSON.stringify(option);
          el.textContent = String(option);
          input.append(el);
        }
        input.value = JSON.stringify(value ?? prop.enum[0]);
        input.dataset.kind = 'enum';
      } else if (prop.type === 'string') {
        input = document.createElement('input');
        input.type = prop.format === 'password' ? 'password' : 'text';
        input.autocomplete = 'off';
        input.value = value ?? '';
        input.dataset.kind = 'string';
      } else if (prop.type === 'number' || prop.type === 'integer') {
        input = document.createElement('input');
        input.type = 'number';
        if (prop.type === 'integer') input.step = '1';
        if (prop.minimum !== undefined) input.min = prop.minimum;
        if (prop.maximum !== undefined) input.max = prop.maximum;
        input.value = value ?? '';
        input.dataset.kind = prop.type;
      } else {
        input = document.createElement('textarea');
        input.spellcheck = false;
        input.value = value === undefined ? '' : JSON.stringify(value, null, 2);
        input.dataset.kind = 'json';
      }
      input.name = key;
      field.append(caption, input);
    }
    box.append(field);
    if (prop.description) {
      const hint = document.createElement('p');
      hint.className = 'hint';
      hint.style.margin = '-8px 0 0';
      hint.textContent = prop.description;
      box.append(hint);
    }
  }
}

function collectPluginSettings() {
  const box = $('plugin-settings-fields');
  const all = box.querySelector('[name="__all"]');
  if (all) {
    const parsed = all.value.trim() ? JSON.parse(all.value) : {};
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(t('Settings must be a JSON object'));
    return parsed;
  }
  const settings = {};
  for (const input of box.querySelectorAll('[data-kind]')) {
    const key = input.name;
    switch (input.dataset.kind) {
      case 'boolean': settings[key] = input.checked; break;
      case 'enum': settings[key] = JSON.parse(input.value); break;
      case 'string': if (input.value !== '') settings[key] = input.value; break;
      case 'number':
      case 'integer':
        if (input.value !== '') settings[key] = Number(input.value);
        break;
      default:
        if (input.value.trim()) {
          try {
            settings[key] = JSON.parse(input.value);
          } catch (err) {
            throw new Error(key + ': ' + err.message);
          }
        }
    }
  }
  return settings;
}

$('plugin-settings').onsubmit = (event) => {
  event.preventDefault();
  let settings;
  try {
    settings = collectPluginSettings();
  } catch (err) {
    showConfigError(err);
    return;
  }
  plugins.formFor = null; // после сохранения — форма из того, что принял сервер
  savePlugin(plugins.current, { settings }, t('Settings saved, the plugin restarts'));
};

// --- лог ---

async function refreshPluginLog() {
  if (currentView !== 'plugin' || !plugins.current) return;
  const lines = await api('api/plugins/' + encodeURIComponent(plugins.current) + '/log');
  const box = $('plugin-log');
  // Лог прокручен к концу — держим его там; читают середину — не дёргаем.
  const atEnd = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  box.textContent = '';
  if (!lines.length) {
    box.textContent = t('Nothing in the log yet.');
    return;
  }
  for (const line of lines) {
    const time = document.createElement('span');
    time.className = 't';
    time.textContent = clock(line.at);
    box.append(time, line.text + '\n');
  }
  if (atEnd) box.scrollTop = box.scrollHeight;
}

// --- страница самого плагина в iframe ---

// Страница плагина вставляется через srcdoc в iframe без allow-same-origin:
// у её скриптов нет ни cookie панели, ни доступа к API. Всё, что ей можно, —
// вызвать свой плагин через window.fairway.call: запрос уходит сообщением
// в панель, панель передаёт его плагину и возвращает ответ.
const PLUGIN_BRIDGE = `<script>(() => {
  let seq = 0;
  const waiting = new Map();
  addEventListener('message', (e) => {
    if (e.source !== parent) return;
    const m = e.data || {};
    const w = waiting.get(m.id);
    if (!w) return;
    waiting.delete(m.id);
    if (m.error) w[1](new Error(m.error)); else w[0](m.result);
  });
  // Тема панели — сразу на корень страницы: color-scheme даёт тёмные фон,
  // текст и поля ввода без единой строки CSS у плагина, а data-theme —
  // зацепку для его собственных стилей.
  document.documentElement.dataset.theme = __THEME__;
  document.documentElement.style.colorScheme = __THEME__;
  window.fairway = {
    lang: __LANG__,
    theme: __THEME__,
    call(method, params) {
      return new Promise((resolve, reject) => {
        const id = ++seq;
        waiting.set(id, [resolve, reject]);
        parent.postMessage({ fairway: 'call', id, method, params }, '*');
      });
    },
  };
  // Высота — по body, а не по документу: документ не бывает ниже самого
  // iframe, и по нему страница только росла бы.
  const report = () => {
    const body = document.body;
    if (!body) return;
    const style = getComputedStyle(body);
    const height = body.getBoundingClientRect().height + parseFloat(style.marginTop) + parseFloat(style.marginBottom);
    parent.postMessage({ fairway: 'height', value: Math.ceil(height) }, '*');
  };
  addEventListener('DOMContentLoaded', () => {
    report();
    new ResizeObserver(report).observe(document.body);
  });
})();<\/script>`;

async function renderPluginFrame(p) {
  const card = $('plugin-ui-card');
  card.hidden = !p.has_ui;
  $('plugin-ui-stopped').hidden = p.state === 'running';
  if (!p.has_ui || plugins.frameFor === p.name) return;
  plugins.frameFor = p.name;
  const resp = await fetch('api/plugins/' + encodeURIComponent(p.name) + '/ui');
  if (!resp.ok) {
    card.hidden = true;
    return;
  }
  const html = await resp.text();
  const bridge = PLUGIN_BRIDGE
    .replace('__LANG__', JSON.stringify(lang))
    .replaceAll('__THEME__', JSON.stringify(isDark() ? 'dark' : 'light'));
  // Мост — до скриптов плагина: они могут звать fairway сразу. Но после
  // <!doctype>: всё, что стоит перед ним, переводит страницу в режим quirks.
  const doctype = html.match(/^\s*<!doctype[^>]*>/i);
  const at = doctype ? doctype[0].length : 0;
  $('plugin-frame').srcdoc = html.slice(0, at) + bridge + html.slice(at);
}

window.addEventListener('message', (event) => {
  const frame = $('plugin-frame');
  if (event.source !== frame.contentWindow || !plugins.frameFor) return;
  const msg = event.data || {};
  if (msg.fairway === 'height') {
    frame.style.height = Math.min(Math.max(Number(msg.value) || 0, 120), 4000) + 'px';
    return;
  }
  if (msg.fairway !== 'call') return;
  const name = plugins.frameFor;
  send('POST', 'api/plugins/' + encodeURIComponent(name) + '/call', { method: String(msg.method || ''), params: msg.params ?? null })
    .then((result) => frame.contentWindow.postMessage({ id: msg.id, result }, '*'))
    .catch((err) => frame.contentWindow.postMessage({ id: msg.id, error: String(err.message || err) }, '*'));
});

refreshPlugins().catch(() => {});
setInterval(() => {
  refreshPlugins().catch(() => {});
  refreshPluginLog().catch(() => {});
}, 3000);

// --- запуск ---

function tick() {
  refreshOverview().catch(() => {});
  refreshDomains().catch(() => {});
  refreshDomain().catch(() => {});
}

tick();
setInterval(tick, 2000);
window.addEventListener('resize', renderChart);

// --- вкладки ---

const views = ['monitor', 'proxies', 'lists', 'rules', 'cert', 'access', 'plugins', 'plugin'];

let currentView = null;

function showView(hash) {
  // Страница плагина — #plugin/<имя>.
  let [name, arg] = hash.split(/\/(.*)/s);
  if (!views.includes(name) || (name === 'plugin' && !arg)) name = 'monitor';
  document.querySelectorAll('.tab[data-view]').forEach((t) => t.classList.toggle('active', t.dataset.view === name));
  $('plugins-tab').classList.toggle('active', name === 'plugins' || name === 'plugin');
  for (const view of views) $('view-' + view).hidden = view !== name;
  // Прокрутка от прошлой вкладки не должна оставаться: иначе новая
  // открывается с середины.
  if (currentView && currentView !== name) window.scrollTo(0, 0);
  currentView = name;
  if (name === 'plugin') openPluginPage(decodeURIComponent(arg));
  else if (name === 'plugins') refreshPlugins().catch(showConfigError);
  else if (name === 'cert') refreshCert().catch(showConfigError);
  else if (name === 'access') refreshAccess().catch(showConfigError);
  else if (name !== 'monitor') refreshSettings().catch(showConfigError);
  if (name === 'rules' && pendingRulePattern !== null) {
    resetRuleForm();
    $('rule-form').pattern.value = pendingRulePattern;
    pendingRulePattern = null;
    openPanel('rule-form-card');
  }
}

document.querySelectorAll('.tab[data-view]').forEach((tab) => {
  // Вкладка пишется в адрес: перезагрузка не сбрасывает её, а на нужный
  // раздел можно дать ссылку.
  tab.onclick = () => { window.location.hash = tab.dataset.view; };
});

window.addEventListener('hashchange', () => showView(window.location.hash.slice(1)));
showView(window.location.hash.slice(1));

// --- раскрывающиеся панели с формами ---

// Формы добавления свёрнуты над таблицами: с полусотней прокси крутить до
// формы внизу пришлось бы каждый раз. Кнопка в шапке страницы открывает и
// закрывает панель, «Изменить» в строке открывает её же с заполненными
// полями, «Закрыть» и «Отмена» сбрасывают форму.
function openPanel(id) {
  const panel = $(id);
  panel.hidden = false;
  document.querySelectorAll(`[data-panel="${id}"]`).forEach((b) => b.classList.add('open'));
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  const first = panel.querySelector('input:not([type="checkbox"]), textarea');
  if (first) first.focus({ preventScroll: true });
}

function closePanel(id) {
  $(id).hidden = true;
  document.querySelectorAll(`[data-panel="${id}"]`).forEach((b) => b.classList.remove('open'));
}

// Что сбросить, закрывая панель: форма могла быть в режиме правки.
const panelReset = {
  'proxy-form-card': () => resetProxyForm(),
  'list-form-card': () => resetListForm(),
  'rule-form-card': () => resetRuleForm(),
};

document.querySelectorAll('[data-panel]').forEach((btn) => {
  btn.onclick = () => {
    const id = btn.dataset.panel;
    const wasHidden = $(id).hidden;
    if (panelReset[id]) panelReset[id]();
    if (wasHidden) openPanel(id); else closePanel(id);
  };
});

document.querySelectorAll('[data-close]').forEach((btn) => {
  btn.onclick = () => {
    const id = btn.dataset.close;
    if (panelReset[id]) panelReset[id]();
    closePanel(id);
  };
});

// --- настройки ---

// Конфиг, показанный в формах последним: редактирование должно идти от того
// же снимка, который видит пользователь.
let settings = { proxies: [], lists: [], domains: [], defaults: {} };

// Что сейчас редактируется. null — форма в режиме добавления.
const editing = { proxy: null, list: null, rule: null };


// Отмеченные галочками прокси — для массовых действий.
const checked = new Set();

// matches ищет подстроку без учёта регистра по всем переданным полям.
function matches(needle, ...fields) {
  if (!needle) return true;
  const query = needle.trim().toLowerCase();
  return fields.some((f) => String(f ?? '').toLowerCase().includes(query));
}

function bindFilter(id, key, rerender) {
  const input = $(id);
  input.oninput = () => {
    filters[key] = input.value;
    rerender();
  };
}

bindFilter('proxy-filter', 'proxy', () => renderProxyTable());
bindFilter('list-filter', 'list', () => renderListTable());
bindFilter('rule-filter', 'rule', () => renderRuleTable());
bindFilter('members-filter', 'members', () => renderListMembers(selectedMembers()));
bindFilter('domain-filter', 'domain', renderDomainList);

const number = (value) => (value === '' ? 0 : Number(value));

async function send(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await resp.text();
  if (!resp.ok) {
    if (resp.status === 501) $('config-readonly').hidden = false;
    throw new Error(text.trim() || t('status {code}', { code: resp.status }));
  }
  return text ? JSON.parse(text) : null;
}

function showConfigError(err) {
  const box = $('config-error');
  box.textContent = String(err.message || err);
  box.hidden = false;
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// edit прогоняет правку и перечитывает конфиг: сервер возвращает применённый
// вариант, и показывать надо именно его, а не то, что мы отправили.
function edit(action, done) {
  $('config-error').hidden = true;
  return action().then(refreshSettings).then(() => toast(done || t('Saved and applied'))).catch(showConfigError);
}

async function refreshSettings() {
  const cfg = await api('api/config');
  settings = {
    proxies: cfg.proxies || [],
    lists: cfg.lists || [],
    domains: cfg.domains || [],
    defaults: cfg.defaults || {},
  };
  // Отметки на исчезнувших прокси снимаем.
  const names = new Set(settings.proxies.map((p) => p.name));
  for (const n of [...checked]) if (!names.has(n)) checked.delete(n);
  renderProxyTable();
  renderListTable();
  if (!editing.list) renderListMembers();
  renderRuleTable();
  fillListSelects();
  fillDefaults();
}

function actionCell(...buttons) {
  const td = document.createElement('td');
  td.className = 'actions';
  td.append(...buttons);
  return td;
}

function button(label, onClick, extra) {
  const el = document.createElement('button');
  el.type = 'button';
  el.textContent = label;
  if (extra) el.className = extra;
  el.onclick = onClick;
  return el;
}

function textCell(value) {
  const td = document.createElement('td');
  if (value === undefined || value === null || value === '') {
    td.textContent = '—';
    td.className = 'dim';
  } else {
    td.textContent = String(value);
  }
  return td;
}

function emptyRow(columns, text) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = columns;
  td.className = 'empty-cell';
  td.textContent = text;
  tr.append(td);
  return tr;
}

// listsOf — в каких листах состоит прокси. Без этой колонки непонятно,
// «работает» прокси или просто заведён и лежит без дела. Листы держат
// прокси по id, поэтому и ищем по id.
function listsOf(id) {
  return settings.lists.filter((l) => (l.proxies || []).includes(id)).map((l) => l.name);
}

// memberNames — имена прокси листа: в самом листе лежат id, а человеку
// нужны имена.
function memberNames(list) {
  const byID = new Map(settings.proxies.map((p) => [p.id, p.name]));
  return (list.proxies || []).map((id) => byID.get(id) || id);
}

// --- прокси ---

function visibleProxies() {
  return settings.proxies.filter((p) =>
    matches(filters.proxy, p.name, p.host, p.country, countryName(p.country), p.comment, p.login, p.port));
}

// countryCode приводит страну прокси к ключу группы: в конфиге её пишут
// руками («ru», « RU»), а плагины — кодом ISO в верхнем регистре.
const countryCode = (country) => String(country ?? '').trim().toUpperCase();

// countryName — название страны на языке панели. Браузер знает названия
// по коду ISO сам; если в поле не код, а произвольный текст, показываем
// его как есть.
function countryName(country) {
  const code = countryCode(country);
  if (!code) return '';
  if (/^[A-Z]{2}$/.test(code)) {
    try {
      const name = new Intl.DisplayNames([lang], { type: 'region' }).of(code);
      if (name && name !== code) return name;
    } catch (e) { /* старый браузер или неизвестный код */ }
  }
  return String(country).trim();
}

// groupByCountry раскладывает прокси по странам: группы по алфавиту
// названий, прокси без страны — последней группой. Внутри группы порядок
// как в конфиге.
function groupByCountry(proxies) {
  const groups = new Map();
  for (const p of proxies) {
    const code = countryCode(p.country);
    if (!groups.has(code)) groups.set(code, { code, name: countryName(p.country), proxies: [] });
    groups.get(code).proxies.push(p);
  }
  return [...groups.values()].sort((a, b) => {
    if (!a.code !== !b.code) return a.code ? -1 : 1;
    return a.name.localeCompare(b.name, locale());
  });
}

const PROXY_COLUMNS = 9;

function renderProxyTable() {
  const body = $('cfg-proxies').querySelector('tbody');
  $('proxy-count').textContent = settings.proxies.length ? `${settings.proxies.length}` : '';
  renderBulkBar();
  if (!settings.proxies.length) {
    body.replaceChildren(emptyRow(PROXY_COLUMNS, t('No proxies yet — add one or paste a list from a price sheet')));
    return;
  }
  const shown = visibleProxies();
  $('proxy-check-all').checked = shown.length > 0 && shown.every((p) => checked.has(p.name));
  if (!shown.length) {
    body.replaceChildren(emptyRow(PROXY_COLUMNS, t('Nothing matches the search')));
    return;
  }
  const groups = groupByCountry(shown);
  // Одна группа «без страны» — заголовок над ней ничего не добавляет.
  if (groups.length === 1 && !groups[0].code) {
    body.replaceChildren(...shown.map(proxyRow));
    return;
  }
  body.replaceChildren(...groups.flatMap((g) => [groupRow(g), ...g.proxies.map(proxyRow)]));
}

// groupRow — заголовок группы стран. Галочка в нём отмечает всю группу,
// чтобы разом добавить, скажем, все немецкие прокси в лист.
function groupRow(group) {
  const tr = document.createElement('tr');
  tr.className = 'group-row';

  const check = document.createElement('td');
  check.className = 'check';
  const box = document.createElement('input');
  box.type = 'checkbox';
  const marked = group.proxies.filter((p) => checked.has(p.name)).length;
  box.checked = marked === group.proxies.length;
  box.indeterminate = marked > 0 && !box.checked;
  box.title = t('Select the whole group');
  box.onchange = () => {
    for (const p of group.proxies) {
      if (box.checked) checked.add(p.name); else checked.delete(p.name);
    }
    renderProxyTable();
  };
  check.append(box);

  const title = document.createElement('td');
  title.colSpan = PROXY_COLUMNS - 1;
  const name = document.createElement('span');
  name.className = 'group-name';
  name.textContent = group.code ? group.name : t('No country');
  title.append(name);
  if (group.code && group.name !== group.code) {
    const flag = document.createElement('span');
    flag.className = 'flag';
    flag.textContent = group.code;
    title.append(' ', flag);
  }
  const count = document.createElement('span');
  count.className = 'group-count';
  count.textContent = group.proxies.length;
  title.append(' ', count);

  tr.append(check, title);
  return tr;
}

function proxyRow(p) {
  const tr = document.createElement('tr');

  const check = document.createElement('td');
  check.className = 'check';
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.checked = checked.has(p.name);
  box.onchange = () => {
    if (box.checked) checked.add(p.name); else checked.delete(p.name);
    // Перерисовка обновит и общую галочку, и галочку группы.
    renderProxyTable();
  };
  check.append(box);

  const name = textCell(p.name);
  name.className = 'name';
  name.title = 'ID: ' + p.id;
  const host = textCell(p.host);
  host.className = 'name';

  const inLists = document.createElement('td');
  const names = listsOf(p.id);
  if (names.length) {
    inLists.append(...names.map((n) => {
      const tag = document.createElement('span');
      tag.className = 'list-tag';
      tag.textContent = n;
      return tag;
    }));
  } else {
    inLists.textContent = t('none');
    inLists.className = 'dim';
    inLists.title = t('The proxy gets no traffic until it is in a list');
  }

  tr.append(
    check,
    name,
    textCell(p.scheme),
    host,
    cell(p.port || '—'),
    textCell(p.login),
    inLists,
    textCell(p.comment),
    actionCell(
      button(t('Edit'), () => startProxyEdit(p), 'ghost'),
      button(t('Delete'), () => {
        if (!confirm(t('Delete proxy {name}? It will disappear from lists too.', { name: p.name }))) return;
        edit(() => send('DELETE', 'api/proxies/' + encodeURIComponent(p.name)), t('Proxy {name} deleted', { name: p.name }));
      }, 'ghost danger'),
    ),
  );
  return tr;
}

$('proxy-check-all').onchange = (event) => {
  for (const p of visibleProxies()) {
    if (event.target.checked) checked.add(p.name); else checked.delete(p.name);
  }
  renderProxyTable();
};

function renderBulkBar() {
  $('bulk-bar').hidden = checked.size === 0;
  $('bulk-count').textContent = checked.size;
  $('list-names').replaceChildren(...settings.lists.map((l) => new Option(l.name)));
}

function bulk(action, list, done) {
  const names = [...checked];
  edit(() => send('POST', 'api/proxies/bulk', { names, action, list }).then(() => {
    if (action === 'delete') checked.clear();
  }), done);
}

$('bulk-add').onclick = () => {
  const list = $('bulk-list').value.trim();
  if (!list) { $('bulk-list').focus(); return; }
  bulk('add_to_list', list, t('Added to list {list}: {n}', { list, n: checked.size }));
};

$('bulk-remove').onclick = () => {
  const list = $('bulk-list').value.trim();
  if (!list) { $('bulk-list').focus(); return; }
  bulk('remove_from_list', list, t('Removed from list {list}: {n}', { list, n: checked.size }));
};

$('bulk-delete').onclick = () => {
  if (!confirm(t('Delete selected proxies ({n})? They will disappear from lists too.', { n: checked.size }))) return;
  bulk('delete', '', t('Proxies deleted: {n}', { n: checked.size }));
};

$('bulk-clear').onclick = () => {
  checked.clear();
  renderProxyTable();
};

function startProxyEdit(proxy) {
  editing.proxy = proxy.name;
  const form = $('proxy-form');
  form.name.value = proxy.name;
  form.scheme.value = proxy.scheme || 'http';
  form.host.value = proxy.host || '';
  form.port.value = proxy.port || '';
  form.login.value = proxy.login || '';
  form.password.value = proxy.password || '';
  form.country.value = proxy.country || '';
  form.comment.value = proxy.comment || '';
  $('proxy-form-title').textContent = t('Edit proxy: {name}', { name: proxy.name });
  $('proxy-form-cancel').hidden = false;
  openPanel('proxy-form-card');
}

function resetProxyForm() {
  editing.proxy = null;
  $('proxy-form').reset();
  $('proxy-form-title').textContent = t('Add proxy');
  $('proxy-form-cancel').hidden = true;
  closePanel('proxy-form-card');
}

$('proxy-form-cancel').onclick = resetProxyForm;

$('proxy-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  const host = form.host.value.trim();
  const proxy = {
    name: form.name.value.trim(),
    login: form.login.value,
    password: form.password.value,
    country: form.country.value.trim(),
    comment: form.comment.value.trim(),
  };
  // Целую строку подключения удобно вставлять прямо из прайса поставщика,
  // поэтому отдаём её серверу как есть — он разложит её по полям.
  if (host.includes('://') || host.split(':').length > 2) {
    proxy.url = host;
  } else {
    proxy.scheme = form.scheme.value;
    proxy.host = host;
    proxy.port = Number(form.port.value);
  }

  const target = editing.proxy;
  edit(() => (target
    ? send('PUT', 'api/proxies/' + encodeURIComponent(target), proxy)
    : send('POST', 'api/proxies', proxy)
  ).then(resetProxyForm), target ? t('Proxy {name} updated', { name: proxy.name }) : t('Proxy {name} added', { name: proxy.name }));
};

// --- листы ---

// usedBy — где лист задействован: в правилах и как лист по умолчанию.
function usedBy(name) {
  const where = settings.domains.filter((d) => d.list === name).map((d) => d.pattern);
  if (settings.defaults.list === name) where.push(t('default'));
  return where;
}

function renderListTable() {
  const body = $('cfg-lists').querySelector('tbody');
  $('list-count').textContent = settings.lists.length ? `${settings.lists.length}` : '';
  if (!settings.lists.length) {
    body.replaceChildren(emptyRow(5, t('No lists yet — create the first one')));
    return;
  }
  const shown = settings.lists.filter((l) => matches(filters.list, l.name, memberNames(l).join(' ')));
  if (!shown.length) {
    body.replaceChildren(emptyRow(5, t('Nothing matches the search')));
    return;
  }
  body.replaceChildren(...shown.map((l) => {
    const tr = document.createElement('tr');
    const name = textCell(l.name);
    name.className = 'name';
    const used = usedBy(l.name);
    const usedCell = document.createElement('td');
    if (used.length) {
      usedCell.append(...used.map((u) => {
        const tag = document.createElement('span');
        tag.className = 'list-tag';
        tag.textContent = u;
        return tag;
      }));
    } else {
      usedCell.textContent = t('nowhere');
      usedCell.className = 'dim';
      usedCell.title = t('No rule references this list');
    }
    tr.append(
      name,
      textCell(memberNames(l).join(', ')),
      cell((l.proxies || []).length),
      usedCell,
      actionCell(
        button(t('Edit'), () => startListEdit(l), 'ghost'),
        button(t('Delete'), () => {
          const warn = used.length ? t(' It is used by: {where} — those rules will need another list.', { where: used.join(', ') }) : '';
          if (!confirm(t('Delete list {name}?{warn}', { name: l.name, warn }))) return;
          edit(() => send('DELETE', 'api/lists/' + encodeURIComponent(l.name)), t('List {name} deleted', { name: l.name }));
        }, 'ghost danger'),
      ),
    );
    return tr;
  }));
}

// renderListMembers рисует прокси столбиком с галочками: набирать имена
// руками — верный способ ошибиться в букве и получить отказ валидации,
// а плитка из имён не даёт разглядеть, что за прокси и откуда он.
function renderListMembers(selected) {
  const chosen = new Set(selected || []);
  const box = $('list-members');
  if (!settings.proxies.length) {
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.textContent = t('No proxies configured yet — add them on the “Proxies” tab.');
    box.replaceChildren(note);
    updateMembersCount();
    return;
  }

  const shown = settings.proxies.filter((p) =>
    chosen.has(p.id) || matches(filters.members, p.name, p.host, p.country, p.comment));
  if (!shown.length) {
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.textContent = t('Nothing matches the search.');
    box.replaceChildren(note);
    updateMembersCount();
    return;
  }
  box.replaceChildren(...shown.map((p) => {
    const row = document.createElement('label');
    row.className = 'member';

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = p.id;
    input.checked = chosen.has(p.id);
    input.onchange = () => {
      row.classList.toggle('checked', input.checked);
      updateMembersCount();
    };

    const name = document.createElement('span');
    name.className = 'member-name';
    name.textContent = p.name;

    const where = document.createElement('span');
    where.className = 'member-where';
    where.textContent = p.port ? `${p.host}:${p.port}` : (p.host || '');

    row.append(input, name);
    if (p.country) {
      const flag = document.createElement('span');
      flag.className = 'flag';
      flag.textContent = p.country;
      row.append(flag);
    }
    row.append(where);
    if (p.comment) {
      const note = document.createElement('span');
      note.className = 'member-note';
      note.textContent = p.comment;
      row.append(note);
    }
    row.classList.toggle('checked', input.checked);
    return row;
  }));
  updateMembersCount();
}

function memberInputs() {
  return [...$('list-members').querySelectorAll('input[type="checkbox"]')];
}

function selectedMembers() {
  return memberInputs().filter((input) => input.checked).map((input) => input.value);
}

function updateMembersCount() {
  const picked = memberInputs().filter((input) => input.checked).length;
  const total = settings.proxies.length;
  const visible = memberInputs().length;
  let text = total ? t('selected {picked} of {total}', { picked, total }) : '';
  if (filters.members && visible !== total) text += t(' · shown {n}', { n: visible });
  $('members-count').textContent = text;
}

function setAllMembers(checkedAll) {
  for (const input of memberInputs()) {
    input.checked = checkedAll;
    input.closest('.member').classList.toggle('checked', checkedAll);
  }
  updateMembersCount();
}

$('members-all').onclick = () => setAllMembers(true);
$('members-none').onclick = () => setAllMembers(false);

function startListEdit(list) {
  editing.list = list.name;
  const form = $('list-form');
  form.name.value = list.name;
  renderListMembers(list.proxies || []);
  $('list-form-title').textContent = t('Edit list: {name}', { name: list.name });
  $('list-form-cancel').hidden = false;
  $('list-rename-hint').hidden = false;
  openPanel('list-form-card');
}

function resetListForm() {
  editing.list = null;
  const form = $('list-form');
  form.reset();
  renderListMembers();
  $('list-form-title').textContent = t('Create list');
  $('list-form-cancel').hidden = true;
  $('list-rename-hint').hidden = true;
  closePanel('list-form-card');
}

$('list-form-cancel').onclick = resetListForm;

$('list-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  const body = { name: form.name.value.trim(), proxies: selectedMembers() };
  const previous = editing.list;
  // Правка идёт по старому имени: сервер переименует и починит ссылки
  // в правилах доменов сам.
  edit(() => (previous
    ? send('PUT', 'api/lists/' + encodeURIComponent(previous), body)
    : send('PUT', 'api/lists', body)
  ).then(resetListForm), previous ? t('List {name} saved', { name: body.name }) : t('List {name} created', { name: body.name }));
};

// --- правила доменов ---

function renderRuleTable() {
  const body = $('cfg-domains').querySelector('tbody');
  $('rule-count').textContent = settings.domains.length ? `${settings.domains.length}` : '';
  if (!settings.domains.length) {
    body.replaceChildren(emptyRow(8, t('No rules yet — all domains follow the general settings')));
    return;
  }
  const shown = settings.domains.filter((d) => matches(filters.rule, d.pattern, d.list));
  if (!shown.length) {
    body.replaceChildren(emptyRow(8, t('Nothing matches the search')));
    return;
  }
  body.replaceChildren(...shown.map((d) => {
    const tr = document.createElement('tr');
    const pattern = textCell(d.pattern);
    pattern.className = 'name';
    // mitm может отсутствовать — это «наследовать», а не «выключено».
    const mitm = (d.mitm === undefined || d.mitm === null)
      ? (settings.defaults.mitm ? t('decrypt (from general)') : t('tunnel (from general)'))
      : (d.mitm ? t('decrypt') : t('tunnel'));
    // Ноль и пустое поле — «как в общих настройках»: показываем значение
    // оттуда, но приглушённо, чтобы было видно, что оно унаследовано.
    const inherited = (own, general, format) => {
      const td = cell(format(own || general || 0));
      if (!own) {
        td.classList.add('dim');
        td.title = t('from general settings');
      }
      return td;
    };
    const limit = (v) => (v === -1 ? t('unlimited') : v || t('unlimited'));
    tr.append(
      pattern,
      textCell(d.list),
      textCell(mitm),
      inherited(d.max_parallel_proxies, settings.defaults.max_parallel_proxies, limit),
      inherited(d.max_conns_per_proxy, settings.defaults.max_conns_per_proxy, limit),
      inherited(d.ban_duration, settings.defaults.ban_duration, (v) => (v ? humanDuration(v) : t('off'))),
      timeoutsCell(d),
      actionCell(
        button(t('Edit'), () => startRuleEdit(d), 'ghost'),
        button(t('Delete'), () => {
          if (!confirm(t('Delete rule {pattern}?', { pattern: d.pattern }))) return;
          edit(() => send('DELETE', 'api/domains/' + encodeURIComponent(d.pattern)), t('Rule {pattern} deleted', { pattern: d.pattern }));
        }, 'ghost danger'),
      ),
    );
    return tr;
  }));
}

// timeoutsCell — «подключение / ответ»; унаследованное приглушено, как
// в соседних колонках.
function timeoutsCell(d) {
  const general = settings.defaults;
  const td = cell(humanDuration(d.connect_timeout || general.connect_timeout)
    + ' / ' + humanDuration(d.response_timeout || general.response_timeout));
  if (!d.connect_timeout && !d.response_timeout) {
    td.classList.add('dim');
    td.title = t('from general settings');
  }
  return td;
}

function startRuleEdit(rule) {
  editing.rule = rule.pattern;
  const form = $('rule-form');
  form.pattern.value = rule.pattern;
  form.list.value = rule.list;
  form.mitm.checked = !!rule.mitm;
  form.max_parallel_proxies.value = rule.max_parallel_proxies ?? '';
  form.max_conns_per_proxy.value = rule.max_conns_per_proxy ?? '';
  form.ban_duration.value = rule.ban_duration || '';
  form.max_ban_duration.value = rule.max_ban_duration || '';
  form.connect_timeout.value = rule.connect_timeout || '';
  form.response_timeout.value = rule.response_timeout || '';
  $('rule-form-title').textContent = t('Edit rule: {pattern}', { pattern: rule.pattern });
  $('rule-form-cancel').hidden = false;
  openPanel('rule-form-card');
}

function resetRuleForm() {
  editing.rule = null;
  $('rule-form').reset();
  $('rule-form-title').textContent = t('Add rule');
  $('rule-form-cancel').hidden = true;
  closePanel('rule-form-card');
}

$('rule-form-cancel').onclick = resetRuleForm;

$('rule-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  const rule = {
    pattern: form.pattern.value.trim(),
    list: form.list.value,
    max_parallel_proxies: number(form.max_parallel_proxies.value),
    max_conns_per_proxy: number(form.max_conns_per_proxy.value),
    ban_duration: form.ban_duration.value.trim(),
    max_ban_duration: form.max_ban_duration.value.trim(),
    connect_timeout: form.connect_timeout.value.trim(),
    response_timeout: form.response_timeout.value.trim(),
  };
  if (form.mitm.checked) rule.mitm = true;

  const previous = editing.rule;
  edit(() => send('PUT', 'api/domains', rule)
    // Паттерн — это имя правила. Если его поменяли, старое надо убрать,
    // иначе один домен окажется описан дважды.
    .then(() => (previous && previous !== rule.pattern
      ? send('DELETE', 'api/domains/' + encodeURIComponent(previous))
      : null))
    .then(resetRuleForm), t('Rule {pattern} saved', { pattern: rule.pattern }));
};

// --- общие настройки ---

function fillListSelects() {
  const names = settings.lists.map((l) => l.name);

  const ruleSelect = $('rule-list-select');
  const rulePrevious = ruleSelect.value;
  ruleSelect.replaceChildren(...names.map((name) => new Option(name, name)));
  if (names.includes(rulePrevious)) ruleSelect.value = rulePrevious;

  const importSelect = $('import-list-select');
  const importPrevious = importSelect.value;
  importSelect.replaceChildren(
    new Option(t('— do not add to a list —'), ''),
    ...names.map((name) => new Option(name, name)),
  );
  if (names.includes(importPrevious)) importSelect.value = importPrevious;

  const defaultsSelect = $('defaults-list-select');
  const defaultsPrevious = defaultsSelect.value;
  defaultsSelect.replaceChildren(
    new Option(t('— not set —'), ''),
    ...names.map((name) => new Option(name, name)),
  );
  defaultsSelect.value = names.includes(defaultsPrevious) ? defaultsPrevious : (settings.defaults.list || '');
}

function fillDefaults() {
  const form = $('defaults-form');
  form.list.value = settings.defaults.list || '';
  form.allow_direct.checked = !!settings.defaults.allow_direct;
  form.mitm.checked = !!settings.defaults.mitm;
  form.max_parallel_proxies.value = settings.defaults.max_parallel_proxies ?? '';
  form.max_conns_per_proxy.value = settings.defaults.max_conns_per_proxy ?? '';
  form.ban_duration.value = settings.defaults.ban_duration || '';
  form.max_ban_duration.value = settings.defaults.max_ban_duration || '';
  form.connect_timeout.value = settings.defaults.connect_timeout || '';
  form.response_timeout.value = settings.defaults.response_timeout || '';
}

$('defaults-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  edit(() => send('PUT', 'api/defaults', {
    list: form.list.value,
    allow_direct: form.allow_direct.checked,
    mitm: form.mitm.checked,
    max_parallel_proxies: number(form.max_parallel_proxies.value),
    max_conns_per_proxy: number(form.max_conns_per_proxy.value),
    ban_duration: form.ban_duration.value.trim(),
    max_ban_duration: form.max_ban_duration.value.trim(),
    connect_timeout: form.connect_timeout.value.trim(),
    response_timeout: form.response_timeout.value.trim(),
  }), t('General settings saved'));
};

document.querySelectorAll('.reload-config').forEach((btn) => {
  btn.onclick = () => edit(() => send('POST', 'api/config/reload'), t('File re-read and applied'));
});

// --- корневой сертификат ---

async function refreshCert() {
  const data = await api('api/ca');
  $('cert-subject').textContent = data.subject;
  $('cert-until').textContent = new Date(data.not_after).toLocaleDateString(locale());
  // Отпечаток разбиваем по два символа: так его сверяют глазами с тем,
  // что показывает системное хранилище.
  $('cert-fingerprint').textContent = (data.fingerprint.match(/../g) || []).join(':');
  $('cert-thumbprint').textContent = (data.trust.thumbprint.match(/../g) || []).join(':');
  $('cert-store').textContent = data.trust.scope
    ? data.trust.store + ' — ' + data.trust.scope
    : data.trust.store;

  const badge = document.createElement('span');
  badge.className = 'badge ' + (data.trust.installed ? 'ok' : 'idle');
  badge.textContent = data.trust.installed ? t('installed in the system') : t('not installed');
  $('cert-state').replaceChildren(badge);

  // На Linux ставить нечем: там всё зависит от дистрибутива и требует root.
  $('cert-install').disabled = !data.trust.supported || data.trust.installed;
  $('cert-uninstall').disabled = !data.trust.supported || !data.trust.installed;
  if (data.trust.hint) $('cert-hint').textContent = data.trust.hint;
}

function certAction(path, done) {
  $('config-error').hidden = true;
  send('POST', path).then(refreshCert).then(() => toast(done)).catch(showConfigError);
}

$('cert-install').onclick = () => certAction('api/ca/install', t('Certificate installed'));
$('cert-uninstall').onclick = () => {
  if (!confirm(t('Remove the Fairway root certificate from the trusted ones on this machine?'))) return;
  certAction('api/ca/uninstall', t('Certificate removed from the system'));
};

// --- импорт прокси списком ---

$('import-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  const body = {
    text: form.text.value,
    scheme: form.scheme.value,
    prefix: form.prefix.value.trim(),
    country: form.country.value.trim(),
    comment: form.comment.value.trim(),
    list: form.list.value,
  };
  $('config-error').hidden = true;
  send('POST', 'api/proxies/import', body)
    .then((result) => {
      renderImportResult(result);
      if (result.added_count) {
        form.text.value = '';
        toast(t('Proxies imported: {n}', { n: result.added_count }));
      }
      return refreshSettings();
    })
    .catch(showConfigError);
};

// Разбор построчный, поэтому и отчёт построчный: «добавлено 47 из 50»
// заставило бы искать три плохие строки глазами.
function renderImportResult(result) {
  const box = $('import-result');
  box.hidden = false;
  box.replaceChildren();

  const summary = document.createElement('p');
  summary.className = result.failed_count ? 'import-warn' : 'import-ok';
  summary.textContent = t('Added {n}', { n: result.added_count }) +
    (result.skipped_count ? t(', duplicates skipped {n}', { n: result.skipped_count }) : '') +
    (result.failed_count ? t(', not parsed {n}', { n: result.failed_count }) : '');
  box.append(summary);

  for (const issue of [...(result.failed || []), ...(result.skipped || [])]) {
    const line = document.createElement('div');
    line.className = 'import-issue';
    const number = document.createElement('span');
    number.className = 'muted';
    number.textContent = t('line {n}', { n: issue.line });
    const text = document.createElement('code');
    text.textContent = issue.text;
    const reason = document.createElement('span');
    reason.className = 'muted';
    reason.textContent = '— ' + issue.reason;
    line.append(number, text, reason);
    box.append(line);
  }
}
