'use strict';

// Панель Fairway. Никакой сборки и зависимостей: файлы вшиты в бинарник,
// график рисуется руками в SVG — тащить ради него библиотеку незачем.

const state = {
  domain: null,
  stream: null,
  events: [],      // события выбранного домена, старые первыми
  maxEvents: 400,
};

const $ = (id) => document.getElementById(id);

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
  const parts = [];
  if (s >= 3600) parts.push(Math.floor(s / 3600) + ' ч');
  if (s >= 60) parts.push(Math.floor((s % 3600) / 60) + ' мин');
  parts.push((s % 60) + ' с');
  return parts.join(' ');
}

const clock = (iso) => new Date(iso).toLocaleTimeString('ru-RU');

// Цвет прокси выводится из имени, чтобы он не прыгал между перерисовками.
function color(name) {
  let hash = 0;
  for (const ch of name) hash = (hash * 31 + ch.codePointAt(0)) >>> 0;
  return `hsl(${hash % 360} 70% 60%)`;
}

async function api(path) {
  const resp = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!resp.ok) throw new Error(path + ': ' + resp.status);
  return resp.json();
}

// --- шапка ---

async function refreshOverview() {
  const data = await api('api/overview');
  $('version').textContent = data.version;
  $('requests').textContent = data.requests.toLocaleString('ru-RU');
  $('proxies').textContent = data.proxies;
  $('domains').textContent = data.domains;
  $('uptime').textContent = duration(data.uptime_sec);
  $('certs').textContent = data.certs_cached;
  $('goroutines').textContent = data.goroutines;
  $('heap').textContent = data.heap_mb.toFixed(1) + ' МБ';
  if (data.config_path) $('config-note').textContent = data.config_path;
  if (data.ca_subject) {
    const until = new Date(data.ca_expires).toLocaleDateString('ru-RU');
    $('ca-info').textContent = `${data.ca_subject} — действует до ${until}`;
  }
}

// --- список доменов ---

async function refreshDomains() {
  const rows = await api('api/domains');
  const list = $('domain-list');
  $('domains-hint').hidden = rows.length > 0;

  list.replaceChildren(...rows.map((row) => {
    const li = document.createElement('li');
    li.className = row.domain === state.domain ? 'active' : '';

    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = row.domain;

    const count = document.createElement('span');
    count.className = 'count';
    count.textContent = row.banned ? `${row.requests} · ${row.banned} бан` : String(row.requests);
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

function renderRule(rule) {
  const chips = [];
  if (!rule.known) {
    chips.push(['правило', 'не найдено — трафик шёл напрямую']);
  } else {
    chips.push(['паттерн', rule.pattern], ['лист', rule.list]);
    chips.push(['MITM', rule.mitm ? 'расшифровка' : 'туннель']);
    chips.push(['параллельно прокси', rule.max_parallel_proxies || 'без ограничения']);
    chips.push(['соединений на прокси', rule.max_conns_per_proxy || 'без ограничения']);
    chips.push(['бан', rule.ban_duration]);
  }
  $('rule').replaceChildren(...chips.map(([label, value]) => {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.append(label + ': ');
    const b = document.createElement('b');
    b.textContent = value;
    chip.append(b);
    return chip;
  }));
}

function badgeClass(proxy) {
  if (proxy.banned) return 'bad';
  switch (proxy.status) {
    case 'ок': return 'ok';
    case 'деградирует': return 'warn';
    default: return 'idle';
  }
}

function renderProxies(proxies) {
  const body = $('proxy-table').querySelector('tbody');
  body.replaceChildren(...proxies.map((p) => {
    const tr = document.createElement('tr');

    const name = document.createElement('td');
    name.className = 'name';
    name.textContent = p.name;
    const upstream = document.createElement('div');
    upstream.className = 'muted';
    upstream.style.fontSize = '11px';
    upstream.textContent = p.upstream || '';
    name.append(upstream);

    const status = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + badgeClass(p);
    badge.textContent = p.banned
      ? 'забанен до ' + new Date(p.banned_until).toLocaleTimeString('ru-RU')
      : p.status;
    status.append(badge);
    if (p.banned && p.ban_reason) {
      const why = document.createElement('div');
      why.className = 'muted';
      why.style.fontSize = '11px';
      why.textContent = p.ban_reason;
      status.append(why);
    }

    const share = document.createElement('td');
    share.className = 'num';
    share.textContent = p.banned ? '—' : percent(p.share);
    if (!p.banned && p.share > 0) {
      const bar = document.createElement('div');
      bar.className = 'bar';
      bar.style.width = Math.max(2, p.share * 100) + '%';
      bar.style.background = color(p.name);
      share.append(bar);
    }

    tr.append(
      name,
      status,
      cell(p.active || '—'),
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
  body.replaceChildren(...recent.map((e) => {
    const tr = document.createElement('tr');
    const status = e.error ? 'ошибка' : (e.status || 'туннель');

    const proxy = document.createElement('td');
    proxy.className = 'name';
    proxy.textContent = e.proxy;

    const statusCell = cell(status, e.error || e.status >= 400 ? 'status-err' : '');
    if (e.error) statusCell.title = e.error;

    tr.append(
      cell(clock(e.at)),
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

// Простой линейный график: по горизонтали время, по вертикали TTFB,
// отдельная линия на каждый прокси.
function renderChart() {
  const svg = $('chart');
  const width = svg.clientWidth || 800;
  const height = svg.clientHeight || 180;
  const pad = { left: 46, right: 8, top: 8, bottom: 18 };
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  const points = state.events.filter((e) => !e.error && e.ttfb_ms > 0);
  if (points.length < 2) {
    svg.replaceChildren(text(width / 2, height / 2, 'мало данных', 'middle'));
    $('legend').replaceChildren();
    return;
  }

  const times = points.map((e) => new Date(e.at).getTime());
  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const maxV = Math.max(...points.map((e) => e.ttfb_ms));
  const spanT = maxT - minT || 1;

  const x = (t) => pad.left + ((t - minT) / spanT) * (width - pad.left - pad.right);
  const y = (v) => height - pad.bottom - (v / maxV) * (height - pad.top - pad.bottom);

  const parts = [];
  // Горизонтальная сетка с подписями.
  for (let i = 0; i <= 2; i++) {
    const value = (maxV / 2) * i;
    const yy = y(value);
    parts.push(line(pad.left, yy, width - pad.right, yy, '#2b313b'));
    parts.push(text(pad.left - 6, yy + 4, Math.round(value) + ' мс', 'end'));
  }

  const byProxy = new Map();
  for (const e of points) {
    if (!byProxy.has(e.proxy)) byProxy.set(e.proxy, []);
    byProxy.get(e.proxy).push(e);
  }

  for (const [proxy, list] of byProxy) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', list.map((e, i) =>
      `${i ? 'L' : 'M'}${x(new Date(e.at).getTime()).toFixed(1)},${y(e.ttfb_ms).toFixed(1)}`).join(' '));
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', color(proxy));
    path.setAttribute('stroke-width', '1.5');
    path.setAttribute('stroke-linejoin', 'round');
    parts.push(path);
  }
  svg.replaceChildren(...parts);

  $('legend').replaceChildren(...[...byProxy.keys()].map((proxy) => {
    const span = document.createElement('span');
    const swatch = document.createElement('i');
    swatch.style.background = color(proxy);
    span.append(swatch, proxy);
    return span;
  }));
}

function line(x1, y1, x2, y2, stroke) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  el.setAttribute('x1', x1); el.setAttribute('y1', y1);
  el.setAttribute('x2', x2); el.setAttribute('y2', y2);
  el.setAttribute('stroke', stroke);
  return el;
}

function text(x, y, value, anchor) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  el.setAttribute('x', x); el.setAttribute('y', y);
  el.setAttribute('fill', '#8b94a3');
  el.setAttribute('font-size', '11');
  el.setAttribute('text-anchor', anchor);
  el.textContent = value;
  return el;
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

document.querySelectorAll('.tab').forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === tab));
    const config = tab.dataset.view === 'config';
    $('view-monitor').hidden = config;
    $('view-config').hidden = !config;
    if (config) refreshConfig().catch(showConfigError);
  };
});

// --- настройки ---

async function send(method, path, body) {
  const resp = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await resp.text();
  if (!resp.ok) {
    if (resp.status === 501) {
      // Конфиг собран из флагов -upstream, сохранять его некуда.
      document.getElementById("config-readonly").hidden = false;
    }
    throw new Error(text.trim() || ('статус ' + resp.status));
  }
  return text ? JSON.parse(text) : null;
}

function showConfigError(err) {
  const box = $('config-error');
  box.textContent = String(err.message || err);
  box.hidden = false;
}

function clearConfigError() {
  $('config-error').hidden = true;
}

async function refreshConfig() {
  const cfg = await api('api/config');
  renderConfigProxies(cfg.proxies || []);
  renderConfigLists(cfg.lists || []);
  renderConfigDomains(cfg.domains || []);
  fillListSelects(cfg.lists || []);
  fillDefaults(cfg.defaults || {});
}

function removeButton(onClick) {
  const td = document.createElement('td');
  const button = document.createElement('button');
  button.className = 'danger';
  button.textContent = 'Удалить';
  button.onclick = onClick;
  td.append(button);
  return td;
}

function textCell(value) {
  const td = document.createElement('td');
  td.textContent = value ?? '';
  return td;
}

function edit(action) {
  clearConfigError();
  action().then(refreshConfig).catch(showConfigError);
}

function renderConfigProxies(proxies) {
  const body = $('cfg-proxies').querySelector('tbody');
  body.replaceChildren(...proxies.map((p) => {
    const tr = document.createElement('tr');
    const name = textCell(p.name);
    name.className = 'name';
    tr.append(
      name,
      textCell(p.url),
      textCell((p.tags || []).join(', ')),
      removeButton(() => edit(() => send('DELETE', 'api/proxies/' + encodeURIComponent(p.name)))),
    );
    return tr;
  }));
}

function renderConfigLists(lists) {
  const body = $('cfg-lists').querySelector('tbody');
  body.replaceChildren(...lists.map((l) => {
    const tr = document.createElement('tr');
    const name = textCell(l.name);
    name.className = 'name';
    tr.append(
      name,
      textCell((l.proxies || []).join(', ')),
      removeButton(() => edit(() => send('DELETE', 'api/lists/' + encodeURIComponent(l.name)))),
    );
    return tr;
  }));
}

function renderConfigDomains(domains) {
  const body = $('cfg-domains').querySelector('tbody');
  body.replaceChildren(...domains.map((d) => {
    const tr = document.createElement('tr');
    const pattern = textCell(d.pattern);
    pattern.className = 'name';
    // mitm может отсутствовать — это «наследовать из defaults», а не «выключено».
    const mitm = d.mitm === undefined || d.mitm === null ? 'из defaults' : (d.mitm ? 'да' : 'нет');
    tr.append(
      pattern,
      textCell(d.list),
      textCell(mitm),
      cell(d.max_parallel_proxies || '—'),
      cell(d.max_conns_per_proxy || '—'),
      textCell(d.ban_duration || '—'),
      removeButton(() => edit(() => send('DELETE', 'api/domains/' + encodeURIComponent(d.pattern)))),
    );
    return tr;
  }));
}

function fillListSelects(lists) {
  for (const id of ['domain-list-select', 'defaults-list-select']) {
    const select = $(id);
    const previous = select.value;
    const options = lists.map((l) => new Option(l.name, l.name));
    if (id === 'defaults-list-select') options.unshift(new Option('— не задан —', ''));
    select.replaceChildren(...options);
    select.value = previous;
  }
}

function fillDefaults(defaults) {
  const form = $('save-defaults');
  form.list.value = defaults.list || '';
  form.allow_direct.checked = !!defaults.allow_direct;
  form.mitm.checked = !!defaults.mitm;
  form.max_parallel_proxies.value = defaults.max_parallel_proxies ?? '';
  form.max_conns_per_proxy.value = defaults.max_conns_per_proxy ?? '';
  form.ban_duration.value = defaults.ban_duration || '';
}

const number = (value) => (value === '' ? 0 : Number(value));
const list = (value) => value.split(',').map((s) => s.trim()).filter(Boolean);

$('add-proxy').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  const proxy = { name: form.name.value.trim(), url: form.url.value.trim() };
  const tags = list(form.tags.value);
  if (tags.length) proxy.tags = tags;
  edit(() => send('POST', 'api/proxies', proxy).then(() => form.reset()));
};

$('save-list').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  edit(() => send('PUT', 'api/lists', {
    name: form.name.value.trim(),
    proxies: list(form.proxies.value),
  }).then(() => form.reset()));
};

$('save-domain').onsubmit = (event) => {
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
  edit(() => send('PUT', 'api/domains', rule).then(() => form.reset()));
};

$('save-defaults').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  edit(() => send('PUT', 'api/defaults', {
    list: form.list.value,
    allow_direct: form.allow_direct.checked,
    mitm: form.mitm.checked,
    max_parallel_proxies: number(form.max_parallel_proxies.value),
    max_conns_per_proxy: number(form.max_conns_per_proxy.value),
    ban_duration: form.ban_duration.value.trim(),
  }));
};

$('reload-config').onclick = () => edit(() => send('POST', 'api/config/reload'));
