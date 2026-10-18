/*
 * ACABELLA web page: form <-> ACABELLA JSON, examples, running the analysis in a worker,
 * and rendering the results. No framework; the form is generated from the specs below.
 */
'use strict';

(function () {
  const BUILD = window.ACABELLA_BUILD || 'dev';
  // Versions of the self-hosted libraries under /vendor (filled in by build.py).
  const VENDOR = window.SITE_VENDOR || { pyodide: '0.27.7', mathjax: '3.2.2' };

  // -------------------------------------------------------------------------
  // Field specs. kind: expr (one expression), list (one per line), model (select),
  // corr (rows of {type, var}). These keys are exactly the JSON keys of the CLI tools.
  // -------------------------------------------------------------------------
  const ACABELLA_SECTIONS = [
    {
      name: 'security', title: 'Security analysis',
      fields: [
        { key: 'key', label: 'Blinding value', kind: 'expr', hint: 'For example alpha * s' },
        { key: 'k', label: 'Key encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
        { key: 'c', label: 'Ciphertext encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
        { key: 'mpk', label: 'Master public key encodings', kind: 'list' },
        { key: 'unknown_vars', label: 'Unknown variables', kind: 'list', hint: 'Variables the attacker does not know' },
        { key: 'corruptable_vars', label: 'Corruptable variables', kind: 'list', hint: 'Optional' },
      ],
    },
    {
      name: 'master_key', title: 'Master-key attack',
      models: ['NoCorruption', 'CA', 'AA', 'mixed_CA_corr', 'mixed_AA_corr'],
      corrTypes: ['MPK_CA', 'MSK_CA', 'MPK_AA', 'MSK_AA'],
      fields: [
        { key: 'master_key', label: 'Master key', kind: 'expr', hint: 'For example alpha' },
        { key: 'corruption_model', label: 'Corruption model', kind: 'model' },
        { key: 'k', label: 'Key encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
        { key: 'unknown_vars', label: 'Unknown variables', kind: 'list' },
        { key: 'corruptable_vars', label: 'Corruptable variables', kind: 'corr', hint: 'Variables the attacker learns by corrupting an authority' },
        { key: 'MPK_CA', label: 'Central authority public key (MPK_CA)', kind: 'list' },
        { key: 'MPK_AA', label: 'Attribute authority public keys (MPK_AA)', kind: 'list' },
        { key: 'MPK_vars', label: 'Other public key variables (MPK_vars)', kind: 'list' },
        { key: 'GP_vars', label: 'Global parameters (GP_vars)', kind: 'list' },
      ],
    },
    {
      name: 'decryption', title: 'Decryption attack',
      models: ['NoCorruption', 'AA', 'AA_extended'],
      corrTypes: ['MPK_AAi', 'MSK_AAi', 'misc'],
      fields: [
        { key: 'key', label: 'Blinding value', kind: 'expr', hint: 'For example alpha * s' },
        { key: 'corruption_model', label: 'Corruption model', kind: 'model' },
        { key: 'k', label: 'Key encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
        { key: 'c', label: 'Ciphertext encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
        { key: 'mpk', label: 'Master public key encodings', kind: 'list' },
        { key: 'gp', label: 'Global parameter encodings', kind: 'list' },
        { key: 'unknown_vars', label: 'Unknown variables', kind: 'list' },
        { key: 'corruptable_vars', label: 'Corruptable variables', kind: 'corr', hint: 'Variables the attacker learns by corrupting an authority' },
        { key: 'MPK_AAi', label: 'Corrupted authority public key (MPK_AAi)', kind: 'list' },
        { key: 'MPK_AAj', label: 'Honest authority public keys (MPK_AAj)', kind: 'list' },
        { key: 'misc_vars', label: 'Other variables (misc_vars)', kind: 'list' },
      ],
    },
  ];
  const ISABELLA_FIELDS = [
    { key: 'key', label: 'Blinding value', kind: 'expr', hint: 'For example stilde' },
    { key: 'mpk', label: 'Master public key variables', kind: 'list' },
    { key: 'k', label: 'Key encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
    { key: 'c', label: 'Ciphertext encodings', kind: 'list', wide: true, hint: 'One polynomial per line' },
    { key: 'known_vars', label: 'Known variables', kind: 'list', hint: 'Constants known to everyone, such as attribute values and matrix entries' },
    { key: 'corruptable_vars', label: 'Corruptable variables', kind: 'list', hint: 'Optional' },
  ];
  const SECTION_BY_NAME = Object.fromEntries(ACABELLA_SECTIONS.map(s => [s.name, s]));
  const SHARED_KEYS = ['key', 'k', 'c', 'mpk', 'unknown_vars'];

  // -------------------------------------------------------------------------
  // Small DOM helpers
  // -------------------------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined) node.append(c);
    return node;
  }
  const fid = (scope, key) => `f-${scope}-${key}`;
  const splitList = text => text.replace(/,/g, '\n').split('\n').map(s => s.trim()).filter(Boolean);

  // -------------------------------------------------------------------------
  // Form construction
  // -------------------------------------------------------------------------
  function buildField(scope, f, section) {
    const id = fid(scope, f.key);
    const wrap = el('div', { class: 'field' + (f.wide ? ' wide' : '') });
    if (f.kind === 'corr') {
      wrap.classList.add('wide');
      wrap.append(el('label', { text: f.label }));
      if (f.hint) wrap.append(el('span', { class: 'hint', text: f.hint }));
      const rows = el('div', { class: 'corr-rows', id });
      wrap.append(rows,
        el('div', {}, el('button', { type: 'button', class: 'link-btn', text: 'Add a variable',
          onclick: () => { addCorrRow(rows, section); refreshJSON(); } })));
      return wrap;
    }
    wrap.append(el('label', { for: id, text: f.label }));
    if (f.kind === 'expr') {
      wrap.append(el('input', { type: 'text', class: 'expr', id, spellcheck: 'false', autocomplete: 'off' }));
    } else if (f.kind === 'model') {
      wrap.append(el('select', { id }, section.models.map(m => el('option', { value: m, text: m }))));
    } else {
      wrap.append(el('textarea', { id, rows: f.wide ? 4 : 3, spellcheck: 'false' }));
    }
    if (f.hint) wrap.append(el('span', { class: 'hint', text: f.hint }));
    return wrap;
  }

  function addCorrRow(rows, section, value = { type: section.corrTypes[0], var: '' }) {
    const sel = el('select', { 'aria-label': 'Where the variable comes from' },
      section.corrTypes.map(t => el('option', { value: t, text: t, selected: t === value.type })));
    const input = el('input', { type: 'text', class: 'expr', value: value.var, placeholder: 'variable',
      'aria-label': 'Corruptable variable', spellcheck: 'false' });
    const row = el('div', { class: 'corr-row' }, sel, input,
      el('button', { type: 'button', class: 'icon-btn', 'aria-label': 'Remove this variable', title: 'Remove',
        onclick: () => { row.remove(); refreshJSON(); } }, el('i', { class: 'fas fa-xmark', 'aria-hidden': 'true' })));
    rows.append(row);
  }

  function buildForms() {
    const holder = $('#acabella-sections');
    for (const s of ACABELLA_SECTIONS) {
      const toggle = el('input', { type: 'checkbox', id: `run-${s.name}`, checked: s.name === 'security' });
      const label = el('label', { class: 'run-toggle', for: `run-${s.name}`,
        onclick: e => e.stopPropagation() }, toggle, 'Include');
      toggle.addEventListener('click', e => e.stopPropagation());
      const fields = el('div', { class: 'fields' }, s.fields.map(f => buildField(s.name, f, s)));
      const content = el('div', { class: 'pub-year-content' });
      if (s.name !== 'security') {
        content.append(el('button', { type: 'button', class: 'link-btn copy-shared',
          text: 'Copy the encodings from the security analysis', onclick: () => copyShared(s.name) }));
      }
      content.append(fields);
      const det = el('details', { class: 'pub-year analysis', id: `sec-${s.name}`, open: s.name === 'security' },
        el('summary', {}, el('span', { text: s.title }), label), content);
      holder.append(det);
      toggle.addEventListener('change', () => { syncSectionState(); if (toggle.checked) det.open = true; });
      if (s.fields.some(f => f.kind === 'corr')) addCorrRow($('#' + fid(s.name, 'corruptable_vars')), s);
    }
    const isa = $('#isabella-fields');
    for (const f of ISABELLA_FIELDS) isa.append(buildField('isabella', f));
    syncSectionState();
  }

  function syncSectionState() {
    for (const s of ACABELLA_SECTIONS) {
      $(`#sec-${s.name}`).classList.toggle('is-off', !$(`#run-${s.name}`).checked);
    }
  }

  function copyShared(target) {
    const spec = SECTION_BY_NAME[target];
    for (const key of SHARED_KEYS) {
      if (!spec.fields.some(f => f.key === key)) continue;
      const src = document.getElementById(fid('security', key));
      const dst = document.getElementById(fid(target, key));
      if (src && dst) dst.value = src.value;
    }
    refreshJSON();
  }

  // -------------------------------------------------------------------------
  // State: read/write the form, convert to and from the CLI JSON format
  // -------------------------------------------------------------------------
  let mode = 'acabella';

  function readFields(scope, fields) {
    const out = {};
    for (const f of fields) {
      const node = document.getElementById(fid(scope, f.key));
      if (f.kind === 'expr' || f.kind === 'model') out[f.key] = node.value.trim();
      else if (f.kind === 'list') out[f.key] = splitList(node.value);
      else if (f.kind === 'corr') {
        out[f.key] = [...node.querySelectorAll('.corr-row')].map(r => ({
          type: r.querySelector('select').value, var: r.querySelector('input').value.trim(),
        })).filter(x => x.var);
      }
    }
    return out;
  }

  function writeFields(scope, fields, data, section) {
    for (const f of fields) {
      const node = document.getElementById(fid(scope, f.key));
      const v = data[f.key];
      if (f.kind === 'expr') node.value = v == null ? '' : String(v);
      else if (f.kind === 'model') node.value = section.models.includes(v) ? v : 'NoCorruption';
      else if (f.kind === 'list') node.value = Array.isArray(v) ? v.map(String).join('\n') : '';
      else if (f.kind === 'corr') {
        node.innerHTML = '';
        const rows = Array.isArray(v) ? v : [];
        rows.forEach(r => addCorrRow(node, section, { type: String(r.type || section.corrTypes[0]), var: String(r.var || '') }));
        if (!rows.length) addCorrRow(node, section);
      }
      if (node.tagName === 'TEXTAREA') node.rows = Math.max(f.wide ? 4 : 3, Math.min(14, node.value.split('\n').length + 1));
    }
  }

  function readState() {
    const state = { mode, scheme_id: $('#scheme_id').value.trim(), enabled: [], sections: {}, isabella: null };
    for (const s of ACABELLA_SECTIONS) {
      if ($(`#run-${s.name}`).checked) state.enabled.push(s.name);
      state.sections[s.name] = readFields(s.name, s.fields);
    }
    state.isabella = readFields('isabella', ISABELLA_FIELDS);
    return state;
  }

  function stateToJSON(state) {
    if (state.mode === 'isabella') {
      return Object.assign({ scheme_id: state.scheme_id, analysis: 'security' }, state.isabella);
    }
    if (state.enabled.length === 1) {
      const name = state.enabled[0];
      return Object.assign({ scheme_id: state.scheme_id, analysis: name }, state.sections[name]);
    }
    const out = { scheme_id: state.scheme_id };
    for (const name of state.enabled) out[name] = Object.assign({ analysis: name }, state.sections[name]);
    return out;
  }

  function emptyFieldsFor(fields, section) {
    const out = {};
    for (const f of fields) out[f.key] = f.kind === 'model' ? section.models[0] : (f.kind === 'expr' ? '' : []);
    return out;
  }

  /** Fill the form from a JSON object in any of the CLI formats. Returns the mode it chose. */
  function applyJSON(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error('The JSON must be an object with fields such as "k" and "c".');
    if (obj.analysis === 'conditional') throw new Error('Conditional attacks are not available on this page yet; use the command-line tool for them.');
    $('#scheme_id').value = obj.scheme_id == null ? '' : String(obj.scheme_id);

    const combined = ACABELLA_SECTIONS.map(s => s.name).filter(n => obj[n] && typeof obj[n] === 'object' && !Array.isArray(obj[n]));
    if (!combined.length && Array.isArray(obj.known_vars)) {
      writeFields('isabella', ISABELLA_FIELDS, obj);
      setMode('isabella');
      return 'isabella';
    }
    let parts = {};
    if (combined.length) combined.forEach(n => { parts[n] = obj[n]; });
    else if (SECTION_BY_NAME[obj.analysis]) parts[obj.analysis] = obj;
    else throw new Error('The JSON needs an "analysis" field of "security", "master_key" or "decryption", or separate sections with those names. ISABELLA descriptions need a "known_vars" field.');

    for (const s of ACABELLA_SECTIONS) {
      const data = parts[s.name] || emptyFieldsFor(s.fields, s);
      writeFields(s.name, s.fields, data, s);
      $(`#run-${s.name}`).checked = !!parts[s.name];
      $(`#sec-${s.name}`).open = !!parts[s.name];
    }
    syncSectionState();
    setMode('acabella');
    return 'acabella';
  }

  function clearForm() {
    $('#scheme_id').value = '';
    for (const s of ACABELLA_SECTIONS) {
      writeFields(s.name, s.fields, emptyFieldsFor(s.fields, s), s);
      $(`#run-${s.name}`).checked = s.name === 'security';
      $(`#sec-${s.name}`).open = s.name === 'security';
    }
    writeFields('isabella', ISABELLA_FIELDS, emptyFieldsFor(ISABELLA_FIELDS, {}));
    syncSectionState();
  }

  function refreshJSON() {
    $('#json-out').textContent = JSON.stringify(stateToJSON(readState()), null, 4);
  }

  // -------------------------------------------------------------------------
  // Validation (friendly messages before Python sees the input)
  // -------------------------------------------------------------------------
  const EXPR_OK = /^[A-Za-z0-9_ \t+\-*/()]*$/;

  function checkExprs(where, values, errors) {
    for (const v of values) {
      if (!EXPR_OK.test(v)) {
        errors.push(`${where}: "${v}" contains characters ACABELLA cannot read. Use variable names, integers, + - * / and parentheses.`);
        return;
      }
    }
  }

  function validate(state) {
    const errors = [];
    if (state.mode === 'isabella') {
      const d = state.isabella;
      if (!d.k.length) errors.push('Add at least one key encoding.');
      if (!d.c.length) errors.push('Add at least one ciphertext encoding.');
      if (!d.key) errors.push('Enter the blinding value.');
      for (const f of ISABELLA_FIELDS) checkExprs(f.label, [].concat(d[f.key] || []), errors);
      return errors;
    }
    if (!state.enabled.length) errors.push('Include at least one analysis.');
    for (const name of state.enabled) {
      const s = SECTION_BY_NAME[name], d = state.sections[name];
      if (!d.k.length) errors.push(`${s.title}: add at least one key encoding.`);
      if ('c' in d && !d.c.length) errors.push(`${s.title}: add at least one ciphertext encoding.`);
      if ('key' in d && !d.key) errors.push(`${s.title}: enter the blinding value.`);
      if ('master_key' in d && !d.master_key) errors.push(`${s.title}: enter the master key.`);
      if (!d.unknown_vars.length) errors.push(`${s.title}: list the unknown variables.`);
      for (const f of s.fields) {
        if (f.kind === 'model') continue;
        const vals = f.kind === 'corr' ? d[f.key].map(x => x.var) : [].concat(d[f.key] || []);
        checkExprs(`${s.title}, ${f.label.toLowerCase()}`, vals, errors);
      }
    }
    return errors;
  }

  function showErrors(errors) {
    const box = $('#form-errors');
    box.innerHTML = '';
    errors.forEach(e => box.append(el('p', { text: e })));
  }

  // -------------------------------------------------------------------------
  // Mode switch and examples
  // -------------------------------------------------------------------------
  let examples = [];

  function setMode(m) {
    mode = m;
    for (const b of document.querySelectorAll('.mode-switch button')) {
      b.setAttribute('aria-selected', String(b.dataset.mode === m));
    }
    $('#panel-acabella').hidden = m !== 'acabella';
    $('#panel-isabella').hidden = m !== 'isabella';
    fillExampleSelect();
    showErrors([]);
    refreshJSON();
  }

  function fillExampleSelect() {
    const sel = $('#example-select');
    const keep = sel.value;
    sel.innerHTML = '';
    sel.append(el('option', { value: '', text: 'An empty form' }));
    for (const ex of examples.filter(e => e.mode === mode)) sel.append(el('option', { value: ex.file, text: ex.label }));
    if ([...sel.options].some(o => o.value === keep)) sel.value = keep;
  }

  async function loadExample(file) {
    if (!file) { clearForm(); refreshJSON(); return; }
    const resp = await fetch(`examples/${file}?v=${BUILD}`);
    if (!resp.ok) throw new Error(`Could not load the example ${file}.`);
    applyJSON(await resp.json());
    $('#example-select').value = file;
    refreshJSON();
  }

  // -------------------------------------------------------------------------
  // Python worker
  // -------------------------------------------------------------------------
  let worker = null, ready = false, pending = null, nextId = 1;

  function setEngine(state, text) {
    $('#engine').dataset.state = state;
    $('#engine-text').textContent = text;
  }

  function startWorker() {
    ready = false;
    $('#run').disabled = true;
    setEngine('loading', 'Loading Python…');
    worker = new Worker(`worker.js?v=${BUILD}&pyodide=${VENDOR.pyodide}`);
    worker.onmessage = ({ data }) => {
      if (data.type === 'status') setEngine('loading', data.text);
      else if (data.type === 'ready') {
        ready = true; $('#run').disabled = false; $('#run-note').textContent = '';
        setEngine('ready', 'Ready');
      } else if (data.type === 'fatal') {
        setEngine('error', 'Python failed to load');
        $('#run-note').textContent = `Python could not be loaded: ${data.text} Reload the page to try again.`;
      } else if ((data.type === 'result' || data.type === 'error') && pending && data.id === pending.id) {
        const p = pending; pending = null;
        finishRun();
        data.type === 'result' ? p.resolve(JSON.parse(data.data)) : p.reject(new Error(data.text));
      }
    };
    worker.onerror = e => { setEngine('error', 'Python failed to load'); $('#run-note').textContent = e.message || ''; };
  }

  function call(fn, payload) {
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending = { id, resolve, reject };
      worker.postMessage({ id, fn, payload: JSON.stringify(payload) });
    });
  }

  function finishRun() {
    $('#run').disabled = !ready;
    $('#run').textContent = 'Run analysis';
    $('#stop').hidden = true;
    setEngine(ready ? 'ready' : 'loading', ready ? 'Ready' : 'Loading Python…');
  }

  function stopRun() {
    if (!pending) return;
    const p = pending; pending = null;
    worker.terminate();
    p.reject(new Error('stopped'));
    startWorker();
    finishRun();
  }

  // -------------------------------------------------------------------------
  // Results
  // -------------------------------------------------------------------------
  let mathjax = null;
  function typeset(node) {
    if (!mathjax) {
      window.MathJax = {
        tex: { inlineMath: [['\\(', '\\)']], displayMath: [['\\[', '\\]']] },
        chtml: { scale: 0.95 },
        startup: { typeset: false },
        // Only the TeX input and HTML output components. The combined tex-chtml.js would also
        // bring MathJax's right-click menu, which reads its saved settings from localStorage.
        loader: { load: ['input/tex', 'output/chtml'] },
      };
      mathjax = new Promise((resolve, reject) => {
        const s = el('script', { src: `../vendor/mathjax-${VENDOR.mathjax}/startup.js`, async: true });
        s.onload = () => window.MathJax.startup.promise.then(resolve);
        s.onerror = reject;
        document.head.append(s);
      });
    }
    return mathjax.then(() => window.MathJax.typesetPromise([node])).catch(() => {});
  }

  function verdictOf(text) {
    const lines = text.split('\n').map(l => l.trim());
    const marked = lines.filter(l => /^\[[*!]\]/.test(l) && !/corresponds to/.test(l));
    if (marked.length) return marked.map(l => l.replace(/^\[[*!]\]\s*/, '')).join('\n');
    const sec = lines.find(l => /secure/i.test(l) && /scheme/i.test(l));
    return sec || null;
  }

  function traceDetails(trace) {
    if (!trace) return null;
    return el('details', {}, el('summary', { text: 'Python traceback' }), el('pre', { text: trace }));
  }

  function renderAcabella(data, scheme) {
    const out = $('#results');
    out.innerHTML = '';
    if (scheme) out.append(el('p', { class: 'body-text', text: `Scheme: ${scheme}` }));
    for (const r of data.results) {
      const box = el('div', { class: 'result' }, el('h3', { text: r.title }));
      if (r.error) {
        box.append(el('p', { class: 'error', text: `ACABELLA stopped: ${r.error}` }), traceDetails(r.trace));
      } else {
        const v = verdictOf(r.output || '');
        if (v) box.append(el('p', { class: 'verdict', text: v }));
        box.append(el('details', { open: !v }, el('summary', { text: 'Full output' }), el('pre', { text: r.output || '' })));
        if (r.proof) {
          box.append(el('details', { open: true }, el('summary', { text: 'Security proof' }),
            r.proof_header ? el('pre', { text: r.proof_header }) : null,
            el('div', { class: 'proof', style: 'white-space: pre-line', text: r.proof })));
        }
      }
      out.append(box);
    }
    typeset(out);
  }

  function renderIsabella(data, scheme) {
    const out = $('#results');
    out.innerHTML = '';
    const box = el('div', { class: 'result' }, el('h3', { text: 'ISABELLA substitution vectors' + (scheme ? ` for ${scheme}` : '') }));
    if (data.note) box.append(el('p', { class: 'body-text', text: data.note, style: 'margin-bottom:0.6rem' }));
    if (data.error) {
      box.append(el('p', { class: 'error', text: data.error.replace(/^ValueError: /, '') }), traceDetails(data.trace));
      out.append(box);
      return;
    }
    box.append(el('p', { class: 'verdict', text: `Found substitution vectors for ${data.vectors.length} variables, so the scheme satisfies the ISABELLA conditions.` }));
    const grid = el('div', { class: 'vectors' });
    for (const v of data.vectors) {
      grid.append(el('div', { class: 'v-name', text: `\\(${v.var_latex}\\)` }), el('div', { class: 'v-val', text: `\\[${v.latex}\\]` }));
    }
    box.append(grid, el('div', { class: 'json-actions', style: 'margin-top:1rem' },
      el('button', { type: 'button', class: 'btn btn-quiet', text: 'Download substitution vectors',
        onclick: () => download(`${scheme || 'scheme'}_substitution_vectors.json`, data.json) })));
    out.append(box);
    typeset(out);
  }

  async function run(e) {
    e.preventDefault();
    const state = readState();
    const errors = validate(state);
    showErrors(errors);
    if (errors.length || !ready) return;

    $('#run').disabled = true; $('#run').textContent = 'Running…';
    $('#stop').hidden = false;
    setEngine('busy', 'Running');
    const card = $('#results-card');
    card.hidden = false;
    $('#results').innerHTML = '';
    $('#results').append(el('p', { class: 'body-text', text: 'Running the analysis…' }));

    try {
      if (state.mode === 'isabella') {
        const data = await call('run_isabella', state.isabella);
        renderIsabella(data, state.scheme_id);
      } else {
        const sections = {};
        state.enabled.forEach(n => { sections[n] = state.sections[n]; });
        const data = await call('run_acabella', { scheme_id: state.scheme_id, sections });
        renderAcabella(data, state.scheme_id);
      }
    } catch (err) {
      $('#results').innerHTML = '';
      $('#results').append(el('p', { class: err.message === 'stopped' ? 'body-text' : 'error',
        text: err.message === 'stopped' ? 'Stopped. Python is restarting; you can run again in a moment.' : `The analysis failed: ${err.message}` }));
    }
    card.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  // -------------------------------------------------------------------------
  // JSON actions and share links
  // -------------------------------------------------------------------------
  function download(name, obj) {
    const blob = new Blob([JSON.stringify(obj, null, 4) + '\n'], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: name.replace(/[^\w.-]+/g, '_') });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const b64encode = s => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b64decode = s => decodeURIComponent(escape(atob(s.replace(/-/g, '+').replace(/_/g, '/'))));

  function flash(button, text) {
    const old = button.textContent;
    button.textContent = text;
    setTimeout(() => { button.textContent = old; }, 1500);
  }

  async function initFromHash() {
    const h = location.hash.slice(1);
    if (h.startsWith('example=')) await loadExample(decodeURIComponent(h.slice(8)));
    else if (h.startsWith('scheme=')) applyJSON(JSON.parse(b64decode(h.slice(7))));
  }

  // -------------------------------------------------------------------------
  // Wire everything up
  // -------------------------------------------------------------------------
  function init() {
    buildForms();
    document.querySelectorAll('.mode-switch button').forEach(b => b.addEventListener('click', () => setMode(b.dataset.mode)));
    $('#scheme-form').addEventListener('input', refreshJSON);
    $('#scheme-form').addEventListener('change', refreshJSON);
    $('#scheme-form').addEventListener('submit', run);
    $('#stop').addEventListener('click', stopRun);
    $('#load-example').addEventListener('click', () =>
      loadExample($('#example-select').value).then(() => showErrors([])).catch(err => showErrors([err.message])));
    $('#toggle-paste').addEventListener('click', () => { const p = $('#paste-json'); p.hidden = !p.hidden; if (!p.hidden) $('#paste-text').focus(); });
    $('#paste-fill').addEventListener('click', () => {
      try {
        applyJSON(JSON.parse($('#paste-text').value));
        refreshJSON(); showErrors([]);
        $('#paste-json').hidden = true;
      } catch (err) {
        showErrors([err instanceof SyntaxError ? `That is not valid JSON: ${err.message}` : err.message]);
      }
    });
    $('#copy-json').addEventListener('click', e => navigator.clipboard.writeText($('#json-out').textContent).then(() => flash(e.target, 'Copied')));
    $('#download-json').addEventListener('click', () => {
      const obj = stateToJSON(readState());
      download(`${obj.scheme_id || 'scheme'}.json`, obj);
    });
    $('#share-link').addEventListener('click', e => {
      const url = `${location.origin}${location.pathname}#scheme=${b64encode(JSON.stringify(stateToJSON(readState())))}`;
      navigator.clipboard.writeText(url).then(() => flash(e.target, 'Link copied'));
    });

    refreshJSON();
    startWorker();
    fetch(`examples/index.json?v=${BUILD}`).then(r => r.json()).then(list => {
      examples = list; fillExampleSelect();
    }).catch(() => {});
    initFromHash().then(refreshJSON).catch(err => showErrors([`Could not open the linked scheme: ${err.message}`]));
  }

  init();
})();
