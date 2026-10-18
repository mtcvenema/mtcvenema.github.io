/*
 * Runs ACABELLA in a Web Worker with Pyodide, so long analyses don't freeze the page
 * and can be stopped by terminating the worker.
 *
 * Everything is loaded from this website: Pyodide, SymPy and mpmath are served from
 * /vendor/pyodide-<version>/ (downloaded once by build.py), so visitors' browsers
 * contact no other server.
 *
 * Messages in:  {id, fn: "run_acabella" | "run_isabella", payload: <JSON string>}
 * Messages out: {type: "status", text} | {type: "ready"} | {type: "fatal", text}
 *               {type: "result", id, data: <JSON string>} | {type: "error", id, text}
 */
'use strict';

const params = new URL(self.location.href).searchParams;
const BUILD = params.get('v') || 'dev';
const PYODIDE_URL = new URL(`../vendor/pyodide-${params.get('pyodide') || '0.27.7'}/`, self.location.href).href;

let runner = null;

async function boot() {
  postMessage({ type: 'status', text: 'Loading Python…' });
  importScripts(PYODIDE_URL + 'pyodide.js');
  const pyodide = await loadPyodide({
    indexURL: PYODIDE_URL,
    // ISABELLA iterates over Python sets; a fixed hash seed makes its output the same on every visit.
    env: { PYTHONHASHSEED: '0', HOME: '/home/pyodide' },
  });

  postMessage({ type: 'status', text: 'Loading SymPy…' });
  await pyodide.loadPackage(['sympy']);   // checked against the sha256 sums in pyodide-lock.json

  postMessage({ type: 'status', text: 'Loading ACABELLA…' });
  const resp = await fetch(`acabella-py.zip?v=${BUILD}`);
  if (!resp.ok) throw new Error(`Could not download acabella-py.zip (HTTP ${resp.status}).`);
  pyodide.unpackArchive(await resp.arrayBuffer(), 'zip', { extractDir: '/home/pyodide/acabella_web' });
  pyodide.runPython("import sys; sys.path.insert(0, '/home/pyodide/acabella_web')");
  runner = pyodide.pyimport('runner');
  postMessage({ type: 'ready' });
}

const booted = boot().catch(err => {
  postMessage({ type: 'fatal', text: String(err && err.message || err) });
  throw err;
});

self.onmessage = async (event) => {
  const { id, fn, payload } = event.data;
  try {
    await booted;
    if (fn !== 'run_acabella' && fn !== 'run_isabella') throw new Error(`Unknown function ${fn}`);
    const data = runner[fn](payload);
    postMessage({ type: 'result', id, data });
  } catch (err) {
    postMessage({ type: 'error', id, text: String(err && err.message || err) });
  }
};
