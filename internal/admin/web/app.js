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
};

// --- утилиты форматирования ---

const ms = (v) => (v === null || v === undefined ? '—' : v < 10 ? v.toFixed(1) + ' мс' : Math.round(v) + ' мс');

function bytes(n) {
  if (!n) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
}

const speed = (v) => (!v ? '—' : bytes(v) + '/с');
const percent = (v) => (v ? (v * 100).toFixed(1) + '%' : '0%');

function duration(sec) {
  const s = Math.floor(sec);
  if (s >= 86400) return Math.floor(s / 86400) + ' д ' + Math.floor((s % 86400) / 3600) + ' ч';
  if (s >= 3600) return Math.floor(s / 3600) + ' ч ' + Math.floor((s % 3600) / 60) + ' мин';
  if (s >= 60) return Math.floor(s / 60) + ' мин ' + (s % 60) + ' с';
  return s + ' с';
}

const clock = (iso) => new Date(iso).toLocaleTimeString('ru-RU');

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
  if (!resp.ok) throw new Error(path + ': ' + resp.status);
  return resp.json();
}

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
  $('requests').textContent = data.requests.toLocaleString('ru-RU');
  $('proxies').textContent = data.proxies;
  $('uptime').textContent = duration(data.uptime_sec);
  $('certs').textContent = data.certs_cached;
  $('goroutines').textContent = data.goroutines;
  $('heap').textContent = data.heap_mb.toFixed(1) + ' МБ';
  $('proxy-addr').textContent = data.proxy_addr || '—';
  $('onboarding-addr').textContent = data.proxy_addr || '—';
  if (data.config_path) {
    document.querySelectorAll('.config-note').forEach((el) => { el.textContent = data.config_path; });
  }
  if (data.ca_subject) {
    const until = new Date(data.ca_expires).toLocaleDateString('ru-RU');
    $('ca-info').textContent = `корневой CA до ${until}`;
  }
  $('config-readonly').hidden = data.editable;
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
  const list = $('domain-list');
  $('domains-hint').hidden = rows.length > 0;
  $('domains').textContent = rows.length;
  $('domains-count').textContent = rows.length ? `${rows.length}` : '';
  renderOnboarding();

  list.replaceChildren(...rows.map((row) => {
    const li = document.createElement('li');
    li.className = row.domain === state.domain ? 'active' : '';

    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = row.domain;

    const count = document.createElement('span');
    count.className = 'count';
    count.textContent = row.banned ? `${row.requests} · ${row.banned} бан` : String(row.requests);
    count.title = row.banned ? `${row.requests} запросов, забанено прокси: ${row.banned}` : `${row.requests} запросов`;
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
    chips.push(chip('правило', 'не найдено — трафик шёл напрямую'));
    link.textContent = 'Добавить правило';
    link.href = '#rules';
    link.dataset.pattern = state.domain;
  } else {
    chips.push(
      chip('паттерн', rule.pattern),
      chip('лист', rule.list),
      chip('TLS', rule.mitm ? 'расшифровка' : 'туннель'),
      chip('прокси разом', rule.max_parallel_proxies || 'без ограничения'),
      chip('соединений на прокси', rule.max_conns_per_proxy || 'без ограничения'),
      chip('бан', humanDuration(rule.ban_duration)),
    );
    link.textContent = 'Изменить правило';
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
  if (m[1] && +m[1]) parts.push(+m[1] + ' ч');
  if (m[2] && +m[2]) parts.push(+m[2] + ' мин');
  if (m[3] && +m[3]) parts.push(+m[3] + ' с');
  return parts.join(' ') || 'выключен';
}

$('rule-edit-link').onclick = (event) => {
  // Переходим на вкладку с уже набранным поиском по нужному паттерну.
  event.preventDefault();
  const pattern = event.currentTarget.dataset.pattern || '';
  filters.rule = pattern;
  $('rule-filter').value = pattern;
  window.location.hash = 'rules';
};

function badgeClass(proxy) {
  if (proxy.banned) return 'bad';
  switch (proxy.status) {
    case 'ок': return 'ok';
    case 'деградирует': return 'warn';
    case 'разведка': return 'info';
    default: return 'idle';
  }
}

function renderProxies(proxies) {
  const body = $('proxy-table').querySelector('tbody');
  if (!proxies.length) {
    body.replaceChildren(emptyRow(9, 'По этому домену ещё нет замеров'));
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
      ? 'забанен до ' + new Date(p.banned_until).toLocaleTimeString('ru-RU')
      : p.status;
    status.append(badge);
    if (p.banned) {
      if (p.ban_reason) {
        const why = document.createElement('span');
        why.className = 'sub';
        why.style.fontFamily = 'inherit';
        why.textContent = p.ban_reason;
        status.append(why);
      }
      const unban = button('Снять бан', () => {
        $('config-error').hidden = true;
        send('POST', `api/domains/${encodeURIComponent(state.domain)}/unban/${encodeURIComponent(p.name)}`)
          .then((data) => { renderProxies(data.proxies); refreshDomains(); toast(`Бан с ${p.name} снят`); })
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
      cell(p.samples ? p.cost.toFixed(3) + ' с' : '—'),
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
    body.replaceChildren(emptyRow(7, 'Запросов ещё не было'));
    return;
  }
  body.replaceChildren(...recent.map((e) => {
    const tr = document.createElement('tr');
    const status = e.error ? 'ошибка' : (e.status || 'туннель');

    const proxy = document.createElement('td');
    proxy.className = 'name';
    proxy.textContent = e.proxy;

    const statusCell = cell(status, e.error || e.status >= 400 ? 'status-err' : '');
    if (e.error) statusCell.title = e.error;

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
const chart = { points: [], x: null, y: null, pad: { left: 52, right: 12, top: 12, bottom: 22 } };

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
    svg.replaceChildren(text(width / 2, height / 2, 'мало данных — нужно хотя бы два успешных запроса', 'middle', textColor));
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
    parts.push(text(pad.left - 8, yy + 4, Math.round(value) + ' мс', 'end', textColor));
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

const views = ['monitor', 'proxies', 'lists', 'rules', 'cert'];

let currentView = null;

function showView(name) {
  if (!views.includes(name)) name = 'monitor';
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === name));
  for (const view of views) $('view-' + view).hidden = view !== name;
  // Прокрутка от прошлой вкладки не должна оставаться: иначе новая
  // открывается с середины.
  if (currentView && currentView !== name) window.scrollTo(0, 0);
  currentView = name;
  if (name === 'cert') refreshCert().catch(showConfigError);
  else if (name !== 'monitor') refreshSettings().catch(showConfigError);
}

document.querySelectorAll('.tab').forEach((tab) => {
  // Вкладка пишется в адрес: перезагрузка не сбрасывает её, а на нужный
  // раздел можно дать ссылку.
  tab.onclick = () => { window.location.hash = tab.dataset.view; };
});

window.addEventListener('hashchange', () => showView(window.location.hash.slice(1)));
showView(window.location.hash.slice(1));

// --- настройки ---

// Конфиг, показанный в формах последним: редактирование должно идти от того
// же снимка, который видит пользователь.
let settings = { proxies: [], lists: [], domains: [], defaults: {} };

// Что сейчас редактируется. null — форма в режиме добавления.
const editing = { proxy: null, list: null, rule: null };

// Строки поиска по таблицам. Когда прокси станет полсотни, глазами их
// не найти, а листать длинную таблицу бессмысленно.
const filters = { proxy: '', list: '', rule: '', members: '' };

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
    throw new Error(text.trim() || ('статус ' + resp.status));
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
  action().then(refreshSettings).then(() => toast(done || 'Сохранено и применено')).catch(showConfigError);
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
// «работает» прокси или просто заведён и лежит без дела.
function listsOf(name) {
  return settings.lists.filter((l) => (l.proxies || []).includes(name)).map((l) => l.name);
}

// --- прокси ---

function visibleProxies() {
  return settings.proxies.filter((p) =>
    matches(filters.proxy, p.name, p.host, p.country, p.comment, p.login, p.port));
}

function renderProxyTable() {
  const body = $('cfg-proxies').querySelector('tbody');
  $('proxy-count').textContent = settings.proxies.length ? `${settings.proxies.length}` : '';
  renderBulkBar();
  if (!settings.proxies.length) {
    body.replaceChildren(emptyRow(10, 'Прокси пока нет — добавьте ниже или вставьте список из прайса'));
    return;
  }
  const shown = visibleProxies();
  $('proxy-check-all').checked = shown.length > 0 && shown.every((p) => checked.has(p.name));
  if (!shown.length) {
    body.replaceChildren(emptyRow(10, 'Под поиск ничего не подошло'));
    return;
  }
  body.replaceChildren(...shown.map((p) => {
    const tr = document.createElement('tr');

    const check = document.createElement('td');
    check.className = 'check';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = checked.has(p.name);
    box.onchange = () => {
      if (box.checked) checked.add(p.name); else checked.delete(p.name);
      renderBulkBar();
      $('proxy-check-all').checked = visibleProxies().every((q) => checked.has(q.name));
    };
    check.append(box);

    const name = textCell(p.name);
    name.className = 'name';
    const host = textCell(p.host);
    host.className = 'name';

    const inLists = document.createElement('td');
    const names = listsOf(p.name);
    if (names.length) {
      inLists.append(...names.map((n) => {
        const tag = document.createElement('span');
        tag.className = 'list-tag';
        tag.textContent = n;
        return tag;
      }));
    } else {
      inLists.textContent = 'ни в одном';
      inLists.className = 'dim';
      inLists.title = 'Прокси не получит трафика, пока не окажется в листе';
    }

    tr.append(
      check,
      name,
      textCell(p.scheme),
      host,
      cell(p.port || '—'),
      textCell(p.login),
      textCell(p.country),
      inLists,
      textCell(p.comment),
      actionCell(
        button('Изменить', () => startProxyEdit(p), 'ghost'),
        button('Удалить', () => {
          if (!confirm(`Удалить прокси ${p.name}? Из листов он тоже исчезнет.`)) return;
          edit(() => send('DELETE', 'api/proxies/' + encodeURIComponent(p.name)), `Прокси ${p.name} удалён`);
        }, 'ghost danger'),
      ),
    );
    return tr;
  }));
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
  bulk('add_to_list', list, `Добавлено в лист ${list}: ${checked.size}`);
};

$('bulk-remove').onclick = () => {
  const list = $('bulk-list').value.trim();
  if (!list) { $('bulk-list').focus(); return; }
  bulk('remove_from_list', list, `Убрано из листа ${list}: ${checked.size}`);
};

$('bulk-delete').onclick = () => {
  if (!confirm(`Удалить отмеченные прокси (${checked.size})? Из листов они тоже исчезнут.`)) return;
  bulk('delete', '', `Удалено прокси: ${checked.size}`);
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
  $('proxy-form-title').textContent = 'Изменить прокси: ' + proxy.name;
  $('proxy-form-cancel').hidden = false;
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  form.name.focus();
}

function resetProxyForm() {
  editing.proxy = null;
  $('proxy-form').reset();
  $('proxy-form-title').textContent = 'Добавить прокси';
  $('proxy-form-cancel').hidden = true;
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
  ).then(resetProxyForm), target ? `Прокси ${proxy.name} изменён` : `Прокси ${proxy.name} добавлен`);
};

// --- листы ---

// usedBy — где лист задействован: в правилах и как лист по умолчанию.
function usedBy(name) {
  const where = settings.domains.filter((d) => d.list === name).map((d) => d.pattern);
  if (settings.defaults.list === name) where.push('по умолчанию');
  return where;
}

function renderListTable() {
  const body = $('cfg-lists').querySelector('tbody');
  $('list-count').textContent = settings.lists.length ? `${settings.lists.length}` : '';
  if (!settings.lists.length) {
    body.replaceChildren(emptyRow(5, 'Листов пока нет — создайте первый ниже'));
    return;
  }
  const shown = settings.lists.filter((l) => matches(filters.list, l.name, (l.proxies || []).join(' ')));
  if (!shown.length) {
    body.replaceChildren(emptyRow(5, 'Под поиск ничего не подошло'));
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
      usedCell.textContent = 'нигде';
      usedCell.className = 'dim';
      usedCell.title = 'Ни одно правило не ссылается на этот лист';
    }
    tr.append(
      name,
      textCell((l.proxies || []).join(', ')),
      cell((l.proxies || []).length),
      usedCell,
      actionCell(
        button('Изменить', () => startListEdit(l), 'ghost'),
        button('Удалить', () => {
          const warn = used.length ? ` Он используется: ${used.join(', ')} — эти правила придётся переназначить.` : '';
          if (!confirm(`Удалить лист ${l.name}?${warn}`)) return;
          edit(() => send('DELETE', 'api/lists/' + encodeURIComponent(l.name)), `Лист ${l.name} удалён`);
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
    note.textContent = 'Прокси ещё не заведены — добавьте их на вкладке «Прокси».';
    box.replaceChildren(note);
    updateMembersCount();
    return;
  }

  const shown = settings.proxies.filter((p) =>
    chosen.has(p.name) || matches(filters.members, p.name, p.host, p.country, p.comment));
  if (!shown.length) {
    const note = document.createElement('div');
    note.className = 'empty-note';
    note.textContent = 'Под поиск ничего не подошло.';
    box.replaceChildren(note);
    updateMembersCount();
    return;
  }
  box.replaceChildren(...shown.map((p) => {
    const row = document.createElement('label');
    row.className = 'member';

    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = p.name;
    input.checked = chosen.has(p.name);
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
  let text = total ? `выбрано ${picked} из ${total}` : '';
  if (filters.members && visible !== total) text += ` · показано ${visible}`;
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
  $('list-form-title').textContent = 'Изменить лист: ' + list.name;
  $('list-form-cancel').hidden = false;
  $('list-rename-hint').hidden = false;
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetListForm() {
  editing.list = null;
  const form = $('list-form');
  form.reset();
  renderListMembers();
  $('list-form-title').textContent = 'Создать лист';
  $('list-form-cancel').hidden = true;
  $('list-rename-hint').hidden = true;
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
  ).then(resetListForm), previous ? `Лист ${body.name} сохранён` : `Лист ${body.name} создан`);
};

// --- правила доменов ---

function renderRuleTable() {
  const body = $('cfg-domains').querySelector('tbody');
  $('rule-count').textContent = settings.domains.length ? `${settings.domains.length}` : '';
  if (!settings.domains.length) {
    body.replaceChildren(emptyRow(7, 'Правил пока нет — все домены идут по общим настройкам'));
    return;
  }
  const shown = settings.domains.filter((d) => matches(filters.rule, d.pattern, d.list));
  if (!shown.length) {
    body.replaceChildren(emptyRow(7, 'Под поиск ничего не подошло'));
    return;
  }
  body.replaceChildren(...shown.map((d) => {
    const tr = document.createElement('tr');
    const pattern = textCell(d.pattern);
    pattern.className = 'name';
    // mitm может отсутствовать — это «наследовать», а не «выключено».
    const mitm = (d.mitm === undefined || d.mitm === null)
      ? (settings.defaults.mitm ? 'расшифровка (из общих)' : 'туннель (из общих)')
      : (d.mitm ? 'расшифровка' : 'туннель');
    // Ноль и пустое поле — «как в общих настройках»: показываем значение
    // оттуда, но приглушённо, чтобы было видно, что оно унаследовано.
    const inherited = (own, general, format) => {
      const td = cell(format(own || general || 0));
      if (!own) {
        td.classList.add('dim');
        td.title = 'из общих настроек';
      }
      return td;
    };
    const limit = (v) => (v === -1 ? 'без ограничения' : v || 'без ограничения');
    tr.append(
      pattern,
      textCell(d.list),
      textCell(mitm),
      inherited(d.max_parallel_proxies, settings.defaults.max_parallel_proxies, limit),
      inherited(d.max_conns_per_proxy, settings.defaults.max_conns_per_proxy, limit),
      inherited(d.ban_duration, settings.defaults.ban_duration, (v) => (v ? humanDuration(v) : 'выключен')),
      actionCell(
        button('Изменить', () => startRuleEdit(d), 'ghost'),
        button('Удалить', () => {
          if (!confirm(`Удалить правило ${d.pattern}?`)) return;
          edit(() => send('DELETE', 'api/domains/' + encodeURIComponent(d.pattern)), `Правило ${d.pattern} удалено`);
        }, 'ghost danger'),
      ),
    );
    return tr;
  }));
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
  $('rule-form-title').textContent = 'Изменить правило: ' + rule.pattern;
  $('rule-form-cancel').hidden = false;
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetRuleForm() {
  editing.rule = null;
  $('rule-form').reset();
  $('rule-form-title').textContent = 'Добавить правило';
  $('rule-form-cancel').hidden = true;
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
  };
  if (form.mitm.checked) rule.mitm = true;

  const previous = editing.rule;
  edit(() => send('PUT', 'api/domains', rule)
    // Паттерн — это имя правила. Если его поменяли, старое надо убрать,
    // иначе один домен окажется описан дважды.
    .then(() => (previous && previous !== rule.pattern
      ? send('DELETE', 'api/domains/' + encodeURIComponent(previous))
      : null))
    .then(resetRuleForm), `Правило ${rule.pattern} сохранено`);
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
    new Option('— не класть в лист —', ''),
    ...names.map((name) => new Option(name, name)),
  );
  if (names.includes(importPrevious)) importSelect.value = importPrevious;

  const defaultsSelect = $('defaults-list-select');
  const defaultsPrevious = defaultsSelect.value;
  defaultsSelect.replaceChildren(
    new Option('— не задан —', ''),
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
  }), 'Общие настройки сохранены');
};

document.querySelectorAll('.reload-config').forEach((btn) => {
  btn.onclick = () => edit(() => send('POST', 'api/config/reload'), 'Файл перечитан и применён');
});

// --- корневой сертификат ---

async function refreshCert() {
  const data = await api('api/ca');
  $('cert-subject').textContent = data.subject;
  $('cert-until').textContent = new Date(data.not_after).toLocaleDateString('ru-RU');
  // Отпечаток разбиваем по два символа: так его сверяют глазами с тем,
  // что показывает системное хранилище.
  $('cert-fingerprint').textContent = (data.fingerprint.match(/../g) || []).join(':');
  $('cert-thumbprint').textContent = (data.trust.thumbprint.match(/../g) || []).join(':');
  $('cert-store').textContent = data.trust.scope
    ? data.trust.store + ' — ' + data.trust.scope
    : data.trust.store;

  const badge = document.createElement('span');
  badge.className = 'badge ' + (data.trust.installed ? 'ok' : 'idle');
  badge.textContent = data.trust.installed ? 'установлен в системе' : 'не установлен';
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

$('cert-install').onclick = () => certAction('api/ca/install', 'Сертификат установлен');
$('cert-uninstall').onclick = () => {
  if (!confirm('Удалить корневой сертификат Fairway из доверенных на этой машине?')) return;
  certAction('api/ca/uninstall', 'Сертификат удалён из системы');
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
        toast(`Импортировано прокси: ${result.added_count}`);
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
  summary.textContent = `Добавлено ${result.added_count}` +
    (result.skipped_count ? `, пропущено дубликатов ${result.skipped_count}` : '') +
    (result.failed_count ? `, не разобрано ${result.failed_count}` : '');
  box.append(summary);

  for (const issue of [...(result.failed || []), ...(result.skipped || [])]) {
    const line = document.createElement('div');
    line.className = 'import-issue';
    const number = document.createElement('span');
    number.className = 'muted';
    number.textContent = 'строка ' + issue.line;
    const text = document.createElement('code');
    text.textContent = issue.text;
    const reason = document.createElement('span');
    reason.className = 'muted';
    reason.textContent = '— ' + issue.reason;
    line.append(number, text, reason);
    box.append(line);
  }
}
