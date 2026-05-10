"""
Obsidian Vault Reorganizer Dashboard
====================================
A simple browser UI for obsidian_reorganize.py. Runs locally; nothing leaves
your machine.

Setup (one time):
    pip install flask

Run:
    python dashboard.py

It will open http://127.0.0.1:5050 in your default browser. Keep both files
(dashboard.py and obsidian_reorganize.py) in the same folder.
"""

import io
import json
import sys
import threading
import time
import webbrowser
from contextlib import redirect_stdout
from pathlib import Path

try:
    from flask import Flask, jsonify, render_template_string, request
except ImportError:
    print('Missing dependency. Install with:\n    pip install flask')
    sys.exit(1)

# ---- import the reorganizer next door --------------------------------------
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
try:
    import obsidian_reorganize as core
except ImportError as e:
    print(f'Could not import obsidian_reorganize.py from {HERE}.\n{e}')
    sys.exit(1)

CONFIG_FILE = HERE / 'dashboard_config.json'
TAXONOMY_LOCK = threading.Lock()


# =============================================================================
# small helpers
# =============================================================================

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {'vault': '', 'top_k': 5, 'threshold': 0.10,
            'cyber_folder': 'cyber domains', 'no_sidecars': False}


def save_config(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                           encoding='utf-8')


def capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            fn(*args, **kwargs)
    except SystemExit:
        pass
    except Exception as e:
        buf.write(f'\nERROR: {type(e).__name__}: {e}\n')
    return buf.getvalue()


def parse_settings(payload):
    cfg = load_config()
    vault = (payload.get('vault') or cfg.get('vault') or '').strip()
    top_k = int(payload.get('top_k') or cfg.get('top_k') or 5)
    threshold = float(payload.get('threshold') or cfg.get('threshold') or 0.10)
    cyber_folder = (payload.get('cyber_folder') or cfg.get('cyber_folder')
                    or 'cyber domains').strip()
    no_sidecars = bool(payload.get('no_sidecars', cfg.get('no_sidecars', False)))
    # persist
    cfg.update({'vault': vault, 'top_k': top_k, 'threshold': threshold,
                'cyber_folder': cyber_folder, 'no_sidecars': no_sidecars})
    save_config(cfg)
    return vault, top_k, threshold, cyber_folder, no_sidecars


# =============================================================================
# Flask app
# =============================================================================

app = Flask(__name__)


@app.route('/')
def index():
    return render_template_string(HTML, config=load_config())


# ---- run / apply / clean ----------------------------------------------------

@app.route('/api/run', methods=['POST'])
def api_run():
    payload = request.get_json(force=True) or {}
    mode = payload.get('mode', 'dry-run')
    vault, top_k, thr, cyber_folder, no_sc = parse_settings(payload)

    vp = Path(vault)
    if not vault or not vp.is_dir():
        return jsonify(ok=False, output=f'Vault path not found: {vault!r}')

    pt, cd = core.load_taxonomy()
    cyber_root = vp / cyber_folder

    if mode == 'dry-run':
        out = capture(core.do_apply, vp, cyber_root, pt, cd,
                      top_k, thr, not no_sc, False, cyber_folder)
    elif mode == 'apply':
        out = capture(core.do_apply, vp, cyber_root, pt, cd,
                      top_k, thr, not no_sc, True, cyber_folder)
    elif mode == 'clean-preview':
        out = capture(core.do_clean, vp, cyber_root, pt, cd, False)
    elif mode == 'clean-apply':
        out = capture(core.do_clean, vp, cyber_root, pt, cd, True)
    else:
        return jsonify(ok=False, output=f'Unknown mode: {mode}')

    return jsonify(ok=True, output=out)


# ---- taxonomy CRUD ----------------------------------------------------------

@app.route('/api/taxonomy', methods=['GET'])
def api_taxonomy():
    pt, cd = core.load_taxonomy()
    return jsonify(primary_topics=pt, cyber_domains=cd)


@app.route('/api/keyword', methods=['POST'])
def api_keyword():
    p = request.get_json(force=True) or {}
    action  = p.get('action')
    topic   = p.get('topic', '').strip()
    keyword = p.get('keyword', '').strip()
    if not topic or not keyword:
        return jsonify(ok=False, message='topic and keyword are required')

    with TAXONOMY_LOCK:
        pt, cd = core.load_taxonomy()
        kind, actual = core.find_topic_or_domain(topic, pt, cd)
        if not actual:
            return jsonify(ok=False, message=f'Unknown: {topic}')
        target = pt if kind == 'primary' else cd

        if action == 'add':
            if keyword in target[actual]:
                return jsonify(ok=False, message=f'"{keyword}" is already in {actual}')
            target[actual].append(keyword)
            msg = f'Added "{keyword}" to {actual}'
        elif action == 'remove':
            if keyword not in target[actual]:
                return jsonify(ok=False, message=f'"{keyword}" not in {actual}')
            target[actual].remove(keyword)
            msg = f'Removed "{keyword}" from {actual}'
        else:
            return jsonify(ok=False, message=f'Unknown action: {action}')

        core.save_taxonomy(pt, cd)
    return jsonify(ok=True, message=msg)


@app.route('/api/topic', methods=['POST'])
def api_topic():
    p = request.get_json(force=True) or {}
    action = p.get('action')
    kind   = p.get('kind')        # 'primary' or 'domain'
    name   = (p.get('name') or '').strip()
    new    = (p.get('new') or '').strip()
    if kind not in ('primary', 'domain'):
        return jsonify(ok=False, message='kind must be primary or domain')
    if not name:
        return jsonify(ok=False, message='name is required')

    with TAXONOMY_LOCK:
        pt, cd = core.load_taxonomy()
        target = pt if kind == 'primary' else cd

        if action == 'add':
            if name in target:
                return jsonify(ok=False, message=f'Already exists: {name}')
            target[name] = []
            msg = f'Created {kind}: {name}'

        elif action == 'remove':
            if name not in target:
                return jsonify(ok=False, message=f'Not found: {name}')
            del target[name]
            msg = f'Deleted {kind}: {name}'

        elif action == 'rename':
            if name not in target:
                return jsonify(ok=False, message=f'Not found: {name}')
            if not new:
                return jsonify(ok=False, message='new name is required')
            if new in target and new != name:
                return jsonify(ok=False, message=f'Already exists: {new}')
            # rebuild preserving order
            rebuilt = {(new if k == name else k): v for k, v in target.items()}
            if kind == 'primary':
                pt = rebuilt
            else:
                cd = rebuilt
            msg = f'Renamed {name} -> {new}'
        else:
            return jsonify(ok=False, message=f'Unknown action: {action}')

        core.save_taxonomy(pt, cd)
    return jsonify(ok=True, message=msg)


# =============================================================================
# HTML
# =============================================================================

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>BMT Vault Reorganizer</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root {
    --bg:#161616; --panel:#1f1f1f; --panel2:#262626; --border:#333;
    --text:#e8e8e8; --muted:#9a9a9a;
    --accent:#7c5cff; --accent-hover:#9075ff;
    --ok:#4ade80; --warn:#fbbf24; --danger:#f87171;
    --mono:'JetBrains Mono','Fira Code',Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{
    margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    background:var(--bg); color:var(--text); font-size:14px; line-height:1.5;
  }
  header{
    padding:16px 24px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:12px; background:var(--panel);
  }
  header h1{margin:0; font-size:18px; font-weight:600}
  header .dot{width:10px; height:10px; border-radius:50%; background:var(--accent)}
  nav.tabs{display:flex; gap:0; background:var(--panel); border-bottom:1px solid var(--border)}
  nav.tabs button{
    background:transparent; color:var(--muted); border:0; padding:12px 24px;
    font-size:14px; cursor:pointer; border-bottom:2px solid transparent;
  }
  nav.tabs button:hover{color:var(--text)}
  nav.tabs button.active{color:var(--text); border-bottom-color:var(--accent)}
  main{max-width:1200px; margin:0 auto; padding:24px}
  .tab-content{display:none}
  .tab-content.active{display:block}

  .card{background:var(--panel); border:1px solid var(--border); border-radius:8px;
        padding:20px; margin-bottom:16px}
  label{display:block; font-size:12px; color:var(--muted); margin-bottom:6px;
        text-transform:uppercase; letter-spacing:0.5px}
  input[type=text], input[type=number]{
    width:100%; background:var(--panel2); color:var(--text);
    border:1px solid var(--border); border-radius:6px; padding:9px 12px;
    font-size:14px; font-family:inherit;
  }
  input[type=text]:focus, input[type=number]:focus{
    outline:none; border-color:var(--accent);
  }
  .row{display:flex; gap:12px; align-items:flex-end}
  .row > div{flex:1}
  .checkbox{display:flex; align-items:center; gap:8px; cursor:pointer; user-select:none}

  button.btn{
    background:var(--panel2); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:10px 18px; font-size:14px; cursor:pointer;
    font-family:inherit; transition:all 0.15s;
  }
  button.btn:hover{border-color:var(--accent); color:var(--accent)}
  button.btn:disabled{opacity:0.5; cursor:not-allowed}
  button.btn.primary{background:var(--accent); color:white; border-color:var(--accent)}
  button.btn.primary:hover{background:var(--accent-hover); color:white}
  button.btn.danger{border-color:var(--danger); color:var(--danger)}
  button.btn.danger:hover{background:var(--danger); color:white}
  .btn-row{display:flex; gap:10px; flex-wrap:wrap; margin-top:12px}

  pre.output{
    background:#0a0a0a; border:1px solid var(--border); border-radius:6px;
    padding:14px; max-height:560px; overflow:auto;
    font-family:var(--mono); font-size:12.5px; white-space:pre-wrap;
    color:#cfcfcf; margin:0;
  }
  pre.output:empty::before{content:"Output will appear here..."; color:var(--muted)}

  .toast{
    position:fixed; bottom:20px; right:20px; padding:12px 18px; border-radius:6px;
    background:var(--panel2); border:1px solid var(--border); font-size:13px;
    box-shadow:0 4px 12px rgba(0,0,0,0.4); z-index:1000;
    animation:slideIn 0.2s ease-out;
  }
  .toast.ok{border-color:var(--ok); color:var(--ok)}
  .toast.err{border-color:var(--danger); color:var(--danger)}
  @keyframes slideIn{from{transform:translateY(20px); opacity:0}}

  /* taxonomy editor */
  .tax-grid{display:grid; grid-template-columns:1fr 1fr; gap:20px}
  @media (max-width:900px){.tax-grid{grid-template-columns:1fr}}
  .tax-col h2{font-size:15px; margin:0 0 12px; display:flex; justify-content:space-between; align-items:center}
  .tax-col h2 .add-topic{
    font-size:12px; padding:5px 10px; border-radius:4px;
    background:transparent; color:var(--muted); border:1px solid var(--border);
    cursor:pointer; font-family:inherit;
  }
  .tax-col h2 .add-topic:hover{color:var(--accent); border-color:var(--accent)}

  .topic-card{
    background:var(--panel); border:1px solid var(--border); border-radius:8px;
    padding:14px; margin-bottom:10px;
  }
  .topic-head{display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:10px}
  .topic-name{
    font-weight:600; font-size:14px; color:var(--text);
    padding:2px 4px; border-radius:3px; outline:none;
  }
  .topic-name[contenteditable=true]{background:var(--panel2); border:1px solid var(--accent)}
  .topic-actions{display:flex; gap:4px; opacity:0.5; transition:opacity 0.15s}
  .topic-card:hover .topic-actions{opacity:1}
  .icon-btn{
    background:transparent; border:0; cursor:pointer; color:var(--muted);
    padding:3px 6px; border-radius:3px; font-size:12px; font-family:inherit;
  }
  .icon-btn:hover{color:var(--text); background:var(--panel2)}
  .icon-btn.danger:hover{color:var(--danger)}

  .chips{display:flex; flex-wrap:wrap; gap:5px; margin-bottom:8px}
  .chip{
    display:inline-flex; align-items:center; gap:5px;
    background:var(--panel2); border:1px solid var(--border);
    padding:3px 4px 3px 9px; border-radius:13px; font-size:12px;
    font-family:var(--mono); color:#d4d4d4;
  }
  .chip .x{
    background:transparent; border:0; color:var(--muted); cursor:pointer;
    width:18px; height:18px; border-radius:50%; padding:0; font-size:14px;
    display:flex; align-items:center; justify-content:center; line-height:1;
  }
  .chip .x:hover{background:var(--danger); color:white}
  .empty{color:var(--muted); font-size:12px; font-style:italic}

  .add-kw{display:flex; gap:6px}
  .add-kw input{flex:1; padding:5px 9px; font-size:12px; font-family:var(--mono)}
  .add-kw button{padding:5px 12px; font-size:12px}

  .help{color:var(--muted); font-size:12.5px; margin-top:6px}
  .help code{background:var(--panel2); padding:1px 5px; border-radius:3px; font-size:12px}
  .small{font-size:12px; color:var(--muted)}

  /* spinner */
  .spinner{display:inline-block; width:12px; height:12px; border:2px solid var(--border);
           border-top-color:var(--accent); border-radius:50%; animation:spin 0.7s linear infinite;
           vertical-align:middle; margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>

<header>
  <span class="dot"></span>
  <h1>BMT Vault Reorganizer</h1>
  <span class="small" style="margin-left:auto">running locally on 127.0.0.1</span>
</header>

<nav class="tabs">
  <button class="active" data-tab="run">Run</button>
  <button data-tab="taxonomy">Taxonomy</button>
</nav>

<main>

  <!-- ============================ RUN TAB ============================ -->
  <section id="tab-run" class="tab-content active">

    <div class="card">
      <label for="vault">Vault folder</label>
      <input type="text" id="vault" value="{{ config.vault }}"
             placeholder="e.g. D:\bayyari\bmt" spellcheck="false" />
      <div class="help">Full path to the folder of notes. Paste it exactly as it
        appears in File Explorer.</div>

      <div class="row" style="margin-top:14px">
        <div>
          <label for="top_k">Top-K related</label>
          <input type="number" id="top_k" value="{{ config.top_k }}" min="0" max="20" />
        </div>
        <div>
          <label for="threshold">Similarity threshold</label>
          <input type="number" id="threshold" value="{{ config.threshold }}" step="0.01" min="0" max="1" />
        </div>
        <div>
          <label for="cyber_folder">Cyber-domains folder name</label>
          <input type="text" id="cyber_folder" value="{{ config.cyber_folder }}" />
        </div>
        <div style="flex:0 0 auto; padding-bottom:9px">
          <label class="checkbox">
            <input type="checkbox" id="no_sidecars" {% if config.no_sidecars %}checked{% endif %} />
            <span>No PDF/DOCX sidecars</span>
          </label>
        </div>
      </div>
    </div>

    <div class="card">
      <label>Actions</label>
      <div class="btn-row">
        <button class="btn"        onclick="run('dry-run')">Dry Run</button>
        <button class="btn primary"  onclick="run('apply')">Apply Changes</button>
        <button class="btn"        onclick="run('clean-preview')">Clean (preview)</button>
        <button class="btn danger" onclick="run('clean-apply')">Clean (apply)</button>
      </div>
      <div class="help" style="margin-top:10px">
        <strong>Dry Run</strong> shows the topic plan without writing anything. &nbsp;
        <strong>Apply</strong> backs up your vault, then writes tags, links, MOC, and the cyber-domains folder. &nbsp;
        <strong>Clean</strong> removes everything this tool added.
      </div>
    </div>

    <div class="card">
      <label>Output</label>
      <pre class="output" id="output"></pre>
    </div>
  </section>

  <!-- ============================ TAXONOMY TAB ============================ -->
  <section id="tab-taxonomy" class="tab-content">
    <div class="card">
      <div class="small">
        Click a topic name to rename it. Add or remove keywords below each topic.
        Changes are saved instantly to <code>taxonomy.json</code>.
      </div>
    </div>
    <div class="tax-grid">
      <div class="tax-col">
        <h2>
          Primary Topics
          <button class="add-topic" onclick="addTopic('primary')">+ New Topic</button>
        </h2>
        <div id="col-primary"></div>
      </div>
      <div class="tax-col">
        <h2>
          Cyber Domains
          <button class="add-topic" onclick="addTopic('domain')">+ New Domain</button>
        </h2>
        <div id="col-domain"></div>
      </div>
    </div>
  </section>

</main>

<script>
// -------- tab switching --------
document.querySelectorAll('nav.tabs button').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('nav.tabs button').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    document.getElementById('tab-' + b.dataset.tab).classList.add('active');
    if (b.dataset.tab === 'taxonomy') loadTaxonomy();
  });
});

// -------- toast --------
function toast(msg, ok=true) {
  const t = document.createElement('div');
  t.className = 'toast ' + (ok ? 'ok' : 'err');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2800);
}

// -------- run actions --------
async function run(mode) {
  const vault = document.getElementById('vault').value.trim();
  if (!vault) { toast('Set the vault path first', false); return; }
  if (mode === 'apply' && !confirm('Apply changes to ' + vault + '?\n\nA timestamped backup will be created first.')) return;
  if (mode === 'clean-apply' && !confirm('Remove ALL auto-generated content from ' + vault + '?\n\nA backup will be created first.')) return;

  const out = document.getElementById('output');
  out.textContent = '';
  const buttons = document.querySelectorAll('.btn-row .btn');
  buttons.forEach(b => b.disabled = true);
  out.innerHTML = '<span class="spinner"></span>Running ' + mode + '...';

  try {
    const r = await fetch('/api/run', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        mode,
        vault,
        top_k: parseInt(document.getElementById('top_k').value),
        threshold: parseFloat(document.getElementById('threshold').value),
        cyber_folder: document.getElementById('cyber_folder').value.trim(),
        no_sidecars: document.getElementById('no_sidecars').checked,
      })
    });
    const data = await r.json();
    out.textContent = data.output || '(no output)';
  } catch (e) {
    out.textContent = 'ERROR: ' + e.message;
  } finally {
    buttons.forEach(b => b.disabled = false);
  }
}

// -------- taxonomy editor --------
async function loadTaxonomy() {
  const r = await fetch('/api/taxonomy');
  const data = await r.json();
  renderColumn('primary', data.primary_topics, document.getElementById('col-primary'));
  renderColumn('domain',  data.cyber_domains,  document.getElementById('col-domain'));
}

function escape(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
          .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function renderColumn(kind, dict, container) {
  const names = Object.keys(dict);
  if (!names.length) { container.innerHTML = '<div class="empty">No entries yet.</div>'; return; }
  container.innerHTML = names.map(name => {
    const kws = dict[name] || [];
    const chips = kws.length
      ? kws.map(kw => `
          <span class="chip">${escape(kw)}
            <button class="x" title="Remove" onclick="removeKw('${escape(name)}','${escape(kw)}')">×</button>
          </span>`).join('')
      : '<span class="empty">No keywords yet.</span>';
    return `
      <div class="topic-card">
        <div class="topic-head">
          <span class="topic-name" data-orig="${escape(name)}"
                onclick="editName(this,'${kind}')"
                onblur="commitName(this,'${kind}')"
                onkeydown="nameKey(event,this)">${escape(name)}</span>
          <div class="topic-actions">
            <button class="icon-btn danger" title="Delete topic"
                    onclick="removeTopic('${kind}','${escape(name)}')">delete</button>
          </div>
        </div>
        <div class="chips">${chips}</div>
        <div class="add-kw">
          <input type="text" placeholder="add keyword..." spellcheck="false"
                 onkeydown="if(event.key==='Enter') addKw(this,'${escape(name)}')" />
          <button class="btn" onclick="addKw(this.previousElementSibling,'${escape(name)}')">Add</button>
        </div>
      </div>`;
  }).join('');
}

async function addKw(input, topic) {
  const kw = input.value.trim();
  if (!kw) return;
  const r = await fetch('/api/keyword', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'add', topic, keyword:kw})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) { input.value=''; loadTaxonomy(); }
}

async function removeKw(topic, keyword) {
  const r = await fetch('/api/keyword', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'remove', topic, keyword})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadTaxonomy();
}

function editName(el) { el.contentEditable = true; el.focus(); selectAll(el); }
function selectAll(el) {
  const r = document.createRange(); r.selectNodeContents(el);
  const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
}
function nameKey(e, el) {
  if (e.key === 'Enter') { e.preventDefault(); el.blur(); }
  if (e.key === 'Escape') { el.textContent = el.dataset.orig; el.blur(); }
}
async function commitName(el, kind) {
  el.contentEditable = false;
  const oldName = el.dataset.orig;
  const newName = el.textContent.trim();
  if (!newName || newName === oldName) { el.textContent = oldName; return; }
  const r = await fetch('/api/topic', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'rename', kind, name:oldName, new:newName})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadTaxonomy(); else el.textContent = oldName;
}

async function addTopic(kind) {
  const label = kind === 'primary' ? 'primary topic' : 'cyber domain';
  const name = prompt('Name for the new ' + label + ':');
  if (!name || !name.trim()) return;
  const r = await fetch('/api/topic', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'add', kind, name:name.trim()})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadTaxonomy();
}

async function removeTopic(kind, name) {
  if (!confirm('Delete "' + name + '" and all its keywords?')) return;
  const r = await fetch('/api/topic', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'remove', kind, name})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadTaxonomy();
}
</script>
</body></html>
"""


# =============================================================================
# main
# =============================================================================

def open_browser_later(url: str):
    time.sleep(0.8)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main():
    # Make sure taxonomy.json exists before we serve.
    core.load_taxonomy()
    url = 'http://127.0.0.1:5050'
    print(f'\n  BMT Vault Reorganizer Dashboard')
    print(f'  → {url}\n')
    print('  Press Ctrl+C to stop.\n')
    threading.Thread(target=open_browser_later, args=(url,), daemon=True).start()
    app.run(host='127.0.0.1', port=5050, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
