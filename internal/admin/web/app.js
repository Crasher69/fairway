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
  if (data.config_path) {
    document.querySelectorAll('.config-note').forEach((el) => { el.textContent = data.config_path; });
  }
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

const views = ['monitor', 'proxies', 'lists', 'rules', 'cert'];

function showView(name) {
  if (!views.includes(name)) name = 'monitor';
  document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.view === name));
  for (const view of views) $('view-' + view).hidden = view !== name;
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
}

// edit прогоняет правку и перечитывает конфиг: сервер возвращает применённый
// вариант, и показывать надо именно его, а не то, что мы отправили.
function edit(action) {
  $('config-error').hidden = true;
  action().then(refreshSettings).catch(showConfigError);
}

async function refreshSettings() {
  const cfg = await api('api/config');
  settings = {
    proxies: cfg.proxies || [],
    lists: cfg.lists || [],
    domains: cfg.domains || [],
    defaults: cfg.defaults || {},
  };
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
  td.textContent = (value === undefined || value === null || value === '') ? '—' : String(value);
  return td;
}

function emptyRow(columns, text) {
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = columns;
  td.className = 'muted';
  td.textContent = text;
  tr.append(td);
  return tr;
}

// --- прокси ---

function renderProxyTable() {
  const body = $('cfg-proxies').querySelector('tbody');
  if (!settings.proxies.length) {
    body.replaceChildren(emptyRow(8, 'Прокси пока нет'));
    return;
  }
  body.replaceChildren(...settings.proxies.map((p) => {
    const tr = document.createElement('tr');
    const name = textCell(p.name);
    name.className = 'name';
    const host = textCell(p.host);
    host.className = 'name';
    tr.append(
      name,
      textCell(p.scheme),
      host,
      cell(p.port || '—'),
      textCell(p.login),
      textCell(p.country),
      textCell(p.comment),
      actionCell(
        button('Изменить', () => startProxyEdit(p)),
        button('Удалить', () => edit(() => send('DELETE', 'api/proxies/' + encodeURIComponent(p.name))), 'danger'),
      ),
    );
    return tr;
  }));
}

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
  ).then(resetProxyForm));
};

// --- листы ---

function renderListTable() {
  const body = $('cfg-lists').querySelector('tbody');
  if (!settings.lists.length) {
    body.replaceChildren(emptyRow(4, 'Листов пока нет'));
    return;
  }
  body.replaceChildren(...settings.lists.map((l) => {
    const tr = document.createElement('tr');
    const name = textCell(l.name);
    name.className = 'name';
    tr.append(
      name,
      textCell((l.proxies || []).join(', ')),
      cell((l.proxies || []).length),
      actionCell(
        button('Изменить', () => startListEdit(l)),
        button('Удалить', () => edit(() => send('DELETE', 'api/lists/' + encodeURIComponent(l.name))), 'danger'),
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

  box.replaceChildren(...settings.proxies.map((p) => {
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
  const all = memberInputs();
  const picked = all.filter((input) => input.checked).length;
  $('members-count').textContent = all.length ? `выбрано ${picked} из ${all.length}` : '';
}

function setAllMembers(checked) {
  for (const input of memberInputs()) {
    input.checked = checked;
    input.closest('.member').classList.toggle('checked', checked);
  }
  updateMembersCount();
}

$('members-all').onclick = () => setAllMembers(true);
$('members-none').onclick = () => setAllMembers(false);

function startListEdit(list) {
  editing.list = list.name;
  const form = $('list-form');
  form.name.value = list.name;
  // Переименование листа сломало бы ссылки в правилах доменов, поэтому
  // при правке имя не меняется.
  form.name.readOnly = true;
  renderListMembers(list.proxies || []);
  $('list-form-title').textContent = 'Изменить лист: ' + list.name;
  $('list-form-cancel').hidden = false;
  form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetListForm() {
  editing.list = null;
  const form = $('list-form');
  form.reset();
  form.name.readOnly = false;
  renderListMembers();
  $('list-form-title').textContent = 'Создать лист';
  $('list-form-cancel').hidden = true;
}

$('list-form-cancel').onclick = resetListForm;

$('list-form').onsubmit = (event) => {
  event.preventDefault();
  const form = event.target;
  edit(() => send('PUT', 'api/lists', {
    name: form.name.value.trim(),
    proxies: selectedMembers(),
  }).then(resetListForm));
};

// --- правила доменов ---

function renderRuleTable() {
  const body = $('cfg-domains').querySelector('tbody');
  if (!settings.domains.length) {
    body.replaceChildren(emptyRow(7, 'Правил пока нет — все домены идут по общим настройкам'));
    return;
  }
  body.replaceChildren(...settings.domains.map((d) => {
    const tr = document.createElement('tr');
    const pattern = textCell(d.pattern);
    pattern.className = 'name';
    // mitm может отсутствовать — это «наследовать», а не «выключено».
    const mitm = (d.mitm === undefined || d.mitm === null) ? 'из общих' : (d.mitm ? 'да' : 'нет');
    tr.append(
      pattern,
      textCell(d.list),
      textCell(mitm),
      cell(d.max_parallel_proxies || '—'),
      cell(d.max_conns_per_proxy || '—'),
      textCell(d.ban_duration),
      actionCell(
        button('Изменить', () => startRuleEdit(d)),
        button('Удалить', () => edit(() => send('DELETE', 'api/domains/' + encodeURIComponent(d.pattern))), 'danger'),
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
    .then(resetRuleForm));
};

// --- общие настройки ---

function fillListSelects() {
  const names = settings.lists.map((l) => l.name);

  const ruleSelect = $('rule-list-select');
  const rulePrevious = ruleSelect.value;
  ruleSelect.replaceChildren(...names.map((name) => new Option(name, name)));
  if (names.includes(rulePrevious)) ruleSelect.value = rulePrevious;

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
  }));
};

document.querySelectorAll('.reload-config').forEach((btn) => {
  btn.onclick = () => edit(() => send('POST', 'api/config/reload'));
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

  const state = $('cert-state');
  state.replaceChildren();
  const badge = document.createElement('span');
  badge.className = 'badge ' + (data.trust.installed ? 'ok' : 'idle');
  badge.textContent = data.trust.installed ? 'установлен' : 'не установлен';
  state.append(badge);

  // На Linux ставить нечем: там всё зависит от дистрибутива и требует root.
  $('cert-install').disabled = !data.trust.supported || data.trust.installed;
  $('cert-uninstall').disabled = !data.trust.supported || !data.trust.installed;
  if (data.trust.hint) $('cert-hint').textContent = data.trust.hint;
}

function certAction(path) {
  $('config-error').hidden = true;
  send('POST', path).then(refreshCert).catch(showConfigError);
}

$('cert-install').onclick = () => certAction('api/ca/install');
$('cert-uninstall').onclick = () => {
  if (!confirm('Удалить корневой сертификат Fairway из доверенных на этой машине?')) return;
  certAction('api/ca/uninstall');
};
