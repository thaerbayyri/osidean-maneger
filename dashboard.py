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
import os
import queue
import signal
import sys
import threading
import time
import webbrowser
from contextlib import redirect_stdout
from pathlib import Path

try:
    from flask import Flask, jsonify, render_template_string, request, Response, stream_with_context
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
RUN_LOCK = threading.Lock()
RUNNING = False
RUN_CANCEL = threading.Event()


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
            'cyber_folder': 'cyber domains', 'no_sidecars': False,
            'folder_tags': False, 'suggest_folder_domains': False,
            'single_domain': False}


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
    raw_k = payload.get('top_k')
    try:
        top_k = int(raw_k) if raw_k is not None else int(cfg.get('top_k', 5))
    except (ValueError, TypeError):
        top_k = int(cfg.get('top_k', 5))
    raw_thr = payload.get('threshold')
    try:
        threshold = float(raw_thr) if raw_thr is not None else float(cfg.get('threshold', 0.10))
    except (ValueError, TypeError):
        threshold = float(cfg.get('threshold', 0.10))
    cyber_folder = (payload.get('cyber_folder') or cfg.get('cyber_folder')
                    or 'cyber domains').strip()
    no_sidecars = bool(payload.get('no_sidecars', cfg.get('no_sidecars', False)))
    folder_tags = bool(payload.get('folder_tags', cfg.get('folder_tags', False)))
    suggest_folder_domains = bool(payload.get(
        'suggest_folder_domains', cfg.get('suggest_folder_domains', False)))
    single_domain = bool(payload.get('single_domain', cfg.get('single_domain', False)))
    # persist
    cfg.update({'vault': vault, 'top_k': top_k, 'threshold': threshold,
                'cyber_folder': cyber_folder, 'no_sidecars': no_sidecars,
                'folder_tags': folder_tags,
                'suggest_folder_domains': suggest_folder_domains,
                'single_domain': single_domain})
    save_config(cfg)
    return (vault, top_k, threshold, cyber_folder, no_sidecars,
            folder_tags, suggest_folder_domains, single_domain)


# =============================================================================
# Queue-based writer for real-time stdout capture (SSE streaming)
# =============================================================================

class _QueueWriter(io.RawIOBase):
    """Forwards each written line into a queue.Queue as it arrives."""
    def __init__(self, q: queue.Queue):
        self._q = q
        self._buf = ''

    def write(self, s):
        self._buf += s
        while '\n' in self._buf:
            line, self._buf = self._buf.split('\n', 1)
            self._q.put(line)
        return len(s)

    def flush(self):
        if self._buf:
            self._q.put(self._buf)
            self._buf = ''

    def readable(self): return False
    def writable(self): return True


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
    global RUNNING
    payload = request.get_json(force=True) or {}
    mode = payload.get('mode', 'dry-run')
    (vault, top_k, thr, cyber_folder, no_sc,
     folder_tags, suggest_folder_domains, single_domain) = parse_settings(payload)

    vp = Path(vault)
    if not vault or not vp.is_dir():
        return jsonify(ok=False, output=f'Vault path not found: {vault!r}')

    pt, cd, rules = core.load_taxonomy()
    cyber_root = vp / cyber_folder

    with RUN_LOCK:
        if RUNNING:
            return jsonify(ok=False, output='A scan is already running.')
        RUNNING = True
        RUN_CANCEL.clear()

    try:
        if mode == 'dry-run':
            out = capture(core.do_apply, vp, cyber_root, pt, cd,
                          rules, top_k, thr, not no_sc, False, cyber_folder,
                          folder_tags, suggest_folder_domains, single_domain,
                          RUN_CANCEL)
        elif mode == 'apply':
            out = capture(core.do_apply, vp, cyber_root, pt, cd,
                          rules, top_k, thr, not no_sc, True, cyber_folder,
                          folder_tags, suggest_folder_domains, single_domain,
                          RUN_CANCEL)
        elif mode == 'clean-preview':
            out = capture(core.do_clean, vp, cyber_root, pt, cd, rules, False,
                          folder_tags, RUN_CANCEL)
        elif mode == 'clean-apply':
            out = capture(core.do_clean, vp, cyber_root, pt, cd, rules, True,
                          folder_tags, RUN_CANCEL)
        else:
            return jsonify(ok=False, output=f'Unknown mode: {mode}')
    finally:
        with RUN_LOCK:
            RUNNING = False

    return jsonify(ok=True, output=out)


@app.route('/api/run-stream')
def api_run_stream():
    global RUNNING
    mode         = request.args.get('mode', 'dry-run')
    vault        = (request.args.get('vault') or '').strip()
    cyber_folder = (request.args.get('cyber_folder') or 'cyber domains').strip()
    no_sc        = request.args.get('no_sidecars', 'false').lower() == 'true'
    folder_tags  = request.args.get('folder_tags', 'false').lower() == 'true'
    suggest_fd   = request.args.get('suggest_folder_domains', 'false').lower() == 'true'
    single_dom   = request.args.get('single_domain', 'false').lower() == 'true'

    cfg = load_config()
    raw_k = request.args.get('top_k')
    try:
        top_k = int(raw_k) if raw_k is not None else int(cfg.get('top_k', 5))
    except (ValueError, TypeError):
        top_k = int(cfg.get('top_k', 5))
    raw_thr = request.args.get('threshold')
    try:
        thr = float(raw_thr) if raw_thr is not None else float(cfg.get('threshold', 0.10))
    except (ValueError, TypeError):
        thr = float(cfg.get('threshold', 0.10))

    vp = Path(vault)
    if not vault or not vp.is_dir():
        def _err():
            yield f'data: ERROR: Vault path not found: {vault!r}\n\n'
            yield 'event: done\ndata: error\n\n'
        return Response(stream_with_context(_err()), mimetype='text/event-stream')

    with RUN_LOCK:
        if RUNNING:
            def _busy():
                yield 'data: ERROR: A scan is already running.\n\n'
                yield 'event: done\ndata: error\n\n'
            return Response(stream_with_context(_busy()), mimetype='text/event-stream')
        RUNNING = True
        RUN_CANCEL.clear()

    line_queue: queue.Queue = queue.Queue()

    def _worker():
        global RUNNING
        writer = _QueueWriter(line_queue)
        try:
            pt, cd, rules = core.load_taxonomy()
            cyber_root = vp / cyber_folder
            with redirect_stdout(writer):
                if mode == 'dry-run':
                    core.do_apply(vp, cyber_root, pt, cd, rules,
                                  top_k, thr, not no_sc, False, cyber_folder,
                                  folder_tags, suggest_fd, single_dom, RUN_CANCEL)
                elif mode == 'apply':
                    core.do_apply(vp, cyber_root, pt, cd, rules,
                                  top_k, thr, not no_sc, True, cyber_folder,
                                  folder_tags, suggest_fd, single_dom, RUN_CANCEL)
                elif mode == 'clean-preview':
                    core.do_clean(vp, cyber_root, pt, cd, rules,
                                  False, folder_tags, RUN_CANCEL)
                elif mode == 'clean-apply':
                    core.do_clean(vp, cyber_root, pt, cd, rules,
                                  True, folder_tags, RUN_CANCEL)
                else:
                    writer.write(f'Unknown mode: {mode}\n')
        except SystemExit:
            pass
        except Exception as e:
            writer.write(f'\nERROR: {type(e).__name__}: {e}\n')
        finally:
            writer.flush()
            with RUN_LOCK:
                RUNNING = False
            line_queue.put(None)

    threading.Thread(target=_worker, daemon=True).start()

    def _generate():
        while True:
            try:
                line = line_queue.get(timeout=30)
            except queue.Empty:
                yield ': keepalive\n\n'
                continue
            if line is None:
                yield 'event: done\ndata: ok\n\n'
                break
            yield f'data: {line.replace(chr(10), " ")}\n\n'

    return Response(
        stream_with_context(_generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ---- taxonomy CRUD ----------------------------------------------------------

@app.route('/api/taxonomy', methods=['GET'])
def api_taxonomy():
    pt, cd, rules = core.load_taxonomy()
    return jsonify(primary_topics=pt, cyber_domains=cd, folder_rules=rules)


@app.route('/api/check-vault')
def api_check_vault():
    raw = (request.args.get('vault') or '').strip()
    if not raw:
        return jsonify(ok=False, exists=False, is_dir=False)
    vp = Path(raw)
    exists = vp.exists()
    is_dir = vp.is_dir() if exists else False
    return jsonify(ok=is_dir, exists=exists, is_dir=is_dir)


# ---- organize: scan-preview + per-file move/copy/tag ------------------------

def _unique_dest(dest_dir: Path, filename: str) -> Path:
    """Return a destination path that doesn't already exist by adding (2), (3)..."""
    target = dest_dir / filename
    if not target.exists():
        return target
    stem = target.stem
    suffix = target.suffix
    i = 2
    while True:
        cand = dest_dir / f'{stem} ({i}){suffix}'
        if not cand.exists():
            return cand
        i += 1


def _backup_vault(vault: Path) -> Path:
    """Create a timestamped backup copy of the vault. Returns the backup path."""
    import shutil as _shutil
    from datetime import datetime
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup = vault.parent / f'{vault.name}-backup-{ts}'
    _shutil.copytree(vault, backup)
    return backup


def _do_file_op(vault: Path, src_rel: str, dest_folder: str, mode: str,
                cyber_folder: str) -> dict:
    """Perform one file operation. Returns {ok, message, final_path}."""
    import shutil as _shutil
    src_rel = (src_rel or '').replace('\\', '/').strip().lstrip('/')
    dest_folder = (dest_folder or '').strip()
    if not src_rel or not dest_folder:
        return {'ok': False, 'message': 'src and dest_folder required'}
    src = (vault / src_rel)
    if not src.is_file():
        return {'ok': False, 'message': f'Source not found: {src_rel}'}

    if mode == 'tag':
        # Tag-only: add domain to frontmatter, no file movement.
        try:
            result = core.apply_domain_to_files(vault, [src_rel], dest_folder,
                                                make_sidecars=False)
            ok = result.get('changed', 0) > 0
            return {'ok': ok,
                    'message': f'Tagged {dest_folder}' if ok else 'Already tagged',
                    'final_path': src_rel}
        except Exception as e:
            return {'ok': False, 'message': f'{type(e).__name__}: {e}'}

    # move / copy: physically place the file in <cyber_folder>/<dest_folder>/
    target_dir = vault / cyber_folder / core.safe_folder_name(dest_folder)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = _unique_dest(target_dir, src.name)
    try:
        if mode == 'move':
            _shutil.move(str(src), str(target))
            action = 'Moved'
        elif mode == 'copy':
            _shutil.copy2(str(src), str(target))
            action = 'Copied'
        else:
            return {'ok': False, 'message': f'Unknown mode: {mode}'}
    except Exception as e:
        return {'ok': False, 'message': f'{type(e).__name__}: {e}'}

    final_rel = str(target.relative_to(vault)).replace('\\', '/')
    return {'ok': True,
            'message': f'{action} to {final_rel}',
            'final_path': final_rel}


@app.route('/api/scan-preview')
def api_scan_preview():
    vault = (request.args.get('vault') or '').strip()
    cyber_folder = (request.args.get('cyber_folder') or 'domains').strip()
    single_domain = request.args.get('single_domain', 'false').lower() == 'true'
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')

    try:
        pt, cd, rules = core.load_taxonomy()
        cyber_root = vp / cyber_folder
        data = core.preview_scan(vp, cyber_root, pt, cd, rules,
                                 single_domain=single_domain)
    except Exception as e:
        return jsonify(ok=False, message=f'{type(e).__name__}: {e}')

    data['ok'] = True
    data['cyber_folder'] = cyber_folder
    return jsonify(data)


@app.route('/api/file-op', methods=['POST'])
def api_file_op():
    p = request.get_json(force=True) or {}
    vault = (p.get('vault') or '').strip()
    cyber_folder = (p.get('cyber_folder') or 'domains').strip()
    mode = (p.get('mode') or '').strip()
    src = p.get('src') or ''
    dest = p.get('dest_folder') or ''
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')
    if mode not in ('move', 'copy', 'tag'):
        return jsonify(ok=False, message='mode must be move, copy, or tag')

    result = _do_file_op(vp, src, dest, mode, cyber_folder)
    return jsonify(**result)


@app.route('/api/file-ops-batch', methods=['POST'])
def api_file_ops_batch():
    p = request.get_json(force=True) or {}
    vault = (p.get('vault') or '').strip()
    cyber_folder = (p.get('cyber_folder') or 'domains').strip()
    ops = p.get('operations') or []
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')
    if not isinstance(ops, list) or not ops:
        return jsonify(ok=False, message='operations list is required')

    # Backup only if at least one op moves/copies bytes
    needs_backup = any((op.get('mode') in ('move', 'copy')) for op in ops)
    backup_path = None
    if needs_backup:
        try:
            backup_path = str(_backup_vault(vp))
        except Exception as e:
            return jsonify(ok=False, message=f'Backup failed: {e}')

    results = []
    applied = 0
    failed = 0
    for op in ops:
        r = _do_file_op(vp, op.get('src', ''), op.get('dest_folder', ''),
                        op.get('mode', ''), cyber_folder)
        r['src'] = op.get('src', '')
        r['dest_folder'] = op.get('dest_folder', '')
        r['mode'] = op.get('mode', '')
        results.append(r)
        if r.get('ok'):
            applied += 1
        else:
            failed += 1

    return jsonify(ok=True, applied=applied, failed=failed,
                   backup=backup_path, results=results)


@app.route('/api/keyword', methods=['POST'])
def api_keyword():
    p = request.get_json(force=True) or {}
    action  = p.get('action')
    topic   = p.get('topic', '').strip()
    keyword = p.get('keyword', '').strip()
    if not topic or not keyword:
        return jsonify(ok=False, message='topic and keyword are required')

    with TAXONOMY_LOCK:
        pt, cd, rules = core.load_taxonomy()
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

        core.save_taxonomy(pt, cd, rules)
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
        pt, cd, rules = core.load_taxonomy()
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

        core.save_taxonomy(pt, cd, rules)
    return jsonify(ok=True, message=msg)


@app.route('/api/folders', methods=['GET'])
def api_folders():
    vault = (request.args.get('vault') or '').strip()
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')

    pt, cd, rules = core.load_taxonomy()
    depth = request.args.get('depth')
    if depth in ('all', 'top'):
        rules['depth'] = depth

    files = list(core.discover(vp, vp / (request.args.get('cyber_folder') or 'cyber domains')))
    counts = core.list_folder_counts(files, vp, rules)
    items = [{'name': k, 'count': v} for k, v in counts.items()]
    return jsonify(ok=True, folders=items, rules=rules)


@app.route('/api/folder-list', methods=['GET'])
def api_folder_list():
    vault = (request.args.get('vault') or '').strip()
    cyber_folder = (request.args.get('cyber_folder') or 'cyber domains').strip()
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')
    cyber_root = vp / cyber_folder

    folders = []
    for p in vp.iterdir():
        if not p.is_dir():
            continue
        if p.name.startswith('.') or p.name.startswith('_'):
            continue
        if p == cyber_root:
            continue
        folders.append(p.name)
    folders.sort(key=str.lower)
    return jsonify(ok=True, folders=folders)


@app.route('/api/files-in-folder', methods=['GET'])
def api_files_in_folder():
    vault = (request.args.get('vault') or '').strip()
    folder = (request.args.get('folder') or '').strip()
    cyber_folder = (request.args.get('cyber_folder') or 'cyber domains').strip()
    if not vault or not folder:
        return jsonify(ok=False, message='vault and folder are required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')
    root = vp / folder
    if not root.is_dir():
        return jsonify(ok=False, message=f'Folder not found: {folder!r}')
    cyber_root = vp / cyber_folder

    files = []
    for p in core.discover(vp, cyber_root):
        try:
            rel = p.relative_to(vp)
        except Exception:
            continue
        if rel.parts[:1] != (folder,):
            continue
        files.append(str(rel).replace('\\', '/'))
    files.sort(key=str.lower)
    return jsonify(ok=True, files=files)


@app.route('/api/folder-rules', methods=['POST'])
def api_folder_rules():
    p = request.get_json(force=True) or {}
    action = p.get('action')
    name = (p.get('name') or '').strip()
    new = (p.get('new') or '').strip()
    depth = p.get('depth')

    with TAXONOMY_LOCK:
        pt, cd, rules = core.load_taxonomy()
        if action == 'set-depth' and depth in ('all', 'top'):
            rules['depth'] = depth
            msg = f'Depth set to {depth}'
        elif action == 'add-exclude' and name:
            if name not in rules['exclude']:
                rules['exclude'].append(name)
            msg = f'Excluded folder: {name}'
        elif action == 'remove-exclude' and name:
            rules['exclude'] = [x for x in rules['exclude'] if x != name]
            msg = f'Removed exclude: {name}'
        elif action == 'rename' and name and new:
            rules['rename'][name] = new
            msg = f'Renamed folder tag: {name} -> {new}'
        elif action == 'remove-rename' and name:
            if name in rules['rename']:
                del rules['rename'][name]
            msg = f'Removed rename: {name}'
        elif action == 'clear':
            rules['exclude'] = []
            rules['rename'] = {}
            msg = 'Cleared folder tag rules'
        else:
            return jsonify(ok=False, message='Invalid action or missing data')

        core.save_taxonomy(pt, cd, rules)
    return jsonify(ok=True, message=msg)


@app.route('/api/folder-domains', methods=['POST'])
def api_folder_domains():
    p = request.get_json(force=True) or {}
    names = p.get('names') or []
    if not isinstance(names, list):
        return jsonify(ok=False, message='names must be a list')

    with TAXONOMY_LOCK:
        pt, cd, rules = core.load_taxonomy()
        added = []
        for name in [n.strip() for n in names if n and n.strip()]:
            if name not in cd:
                cd[name] = []
                added.append(name)
        core.save_taxonomy(pt, cd, rules)
    return jsonify(ok=True, message=f'Added {len(added)} domain(s).', added=added)


@app.route('/api/assign-domain', methods=['POST'])
def api_assign_domain():
    p = request.get_json(force=True) or {}
    vault = (p.get('vault') or '').strip()
    domain = (p.get('domain') or '').strip()
    files = p.get('files') or []
    make_sidecars = bool(p.get('make_sidecars', True))
    create_domain = bool(p.get('create_domain', True))
    if not vault or not domain or not files:
        return jsonify(ok=False, message='vault, domain, and files are required')

    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')

    with TAXONOMY_LOCK:
        pt, cd, rules = core.load_taxonomy()
        if create_domain and domain not in cd:
            cd[domain] = []
            core.save_taxonomy(pt, cd, rules)

    result = core.apply_domain_to_files(vp, files, domain, make_sidecars)
    return jsonify(ok=True, message='Domain tags applied', result=result)


@app.route('/api/remove-folder-tags', methods=['POST'])
def api_remove_folder_tags():
    p = request.get_json(force=True) or {}
    vault = (p.get('vault') or '').strip()
    slugs = p.get('slugs') or []
    mode = p.get('mode')
    if not vault:
        return jsonify(ok=False, message='vault is required')
    vp = Path(vault)
    if not vp.is_dir():
        return jsonify(ok=False, message=f'Vault path not found: {vault!r}')
    if mode == 'all':
        pt, cd, rules = core.load_taxonomy()
        files = list(core.discover(vp, vp / (p.get('cyber_folder') or 'cyber domains')))
        slug_set = set()
        for f in files:
            slug_set.update(core.folder_tag_slugs(f, vp, rules))
        slugs = sorted(slug_set)

    out = capture(core.remove_folder_tags_from_notes, vp,
                  vp / (p.get('cyber_folder') or 'cyber domains'),
                  slugs, True)
    return jsonify(ok=True, output=out)


@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    def _stop():
        time.sleep(0.4)
        os.kill(os.getpid(), signal.SIGTERM)
    threading.Thread(target=_stop, daemon=True).start()
    return jsonify(ok=True, message='Server shutting down...')


@app.route('/api/stop-scan', methods=['POST'])
def api_stop_scan():
    RUN_CANCEL.set()
    return jsonify(ok=True, message='Stop requested')


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

  /* folder list */
  .folder-row{display:flex; gap:10px; align-items:center; padding:8px 10px;
              background:var(--panel2); border:1px solid var(--border);
              border-radius:6px; margin-bottom:8px}
  .folder-name{font-weight:600}
  .folder-count{color:var(--muted); font-size:12px}
  .folder-actions{margin-left:auto; display:flex; gap:6px; flex-wrap:wrap}
  .folder-actions .btn{padding:6px 10px; font-size:12px}

  /* spinner */
  .spinner{display:inline-block; width:12px; height:12px; border:2px solid var(--border);
           border-top-color:var(--accent); border-radius:50%; animation:spin 0.7s linear infinite;
           vertical-align:middle; margin-right:6px}
  @keyframes spin{to{transform:rotate(360deg)}}

  /* vault path status indicator */
  #vault-status{font-size:16px; flex-shrink:0; line-height:1; min-width:18px; text-align:center}
  #vault-status.ok{color:var(--ok)}
  #vault-status.err{color:var(--danger)}
  #vault-status.checking{color:var(--muted); font-size:12px}

  /* taxonomy search */
  .tax-search-wrap{position:relative; margin-bottom:12px}
  .tax-search-wrap input{
    width:100%; padding:7px 32px 7px 10px;
    background:var(--panel2); border:1px solid var(--border);
    border-radius:6px; color:var(--text); font-size:13px; font-family:inherit;
  }
  .tax-search-wrap input:focus{outline:none; border-color:var(--accent)}
  .tax-search-clear{
    position:absolute; right:8px; top:50%; transform:translateY(-50%);
    background:transparent; border:0; color:var(--muted); cursor:pointer;
    font-size:16px; padding:0; line-height:1;
  }
  .tax-search-clear:hover{color:var(--text)}
  .topic-card.hidden{display:none}

  /* organize / drag-drop */
  .file-dot{
    width:14px; height:14px; border-radius:50%;
    display:inline-block; margin:3px; cursor:grab;
    border:2px solid transparent; vertical-align:middle;
    transition:transform 0.1s;
  }
  .file-dot:hover{transform:scale(1.3)}
  .file-dot:active{cursor:grabbing}
  .file-dot.suggested{border-style:dashed; border-color:var(--muted)}
  .file-dot.staged{border-color:var(--accent); border-style:solid}
  .file-dot.pending{box-shadow:0 0 0 2px gold}
  .file-dot.placed{border-color:var(--ok); border-style:solid}

  .folder-group{margin-bottom:10px}
  .folder-group-head{
    display:flex; align-items:center; gap:6px;
    font-size:12px; color:var(--muted); margin-bottom:4px;
    cursor:pointer; user-select:none;
  }
  .folder-group-head:hover{color:var(--text)}
  .folder-group-body{padding-left:14px; line-height:1.8}
  .folder-group.collapsed .folder-group-body{display:none}

  .domain-grid{
    display:grid; grid-template-columns:repeat(auto-fill, minmax(180px, 1fr));
    gap:10px;
  }
  .domain-bin{
    min-height:80px; padding:8px 10px;
    border:1px dashed var(--border); border-radius:6px;
    background:var(--panel2);
  }
  .domain-bin.dragover{background:#2a2440; border-color:var(--accent); border-style:solid}
  .domain-bin-name{font-size:12px; font-weight:600; color:var(--muted);
                   margin-bottom:6px; text-transform:uppercase; letter-spacing:0.4px}
  .domain-bin-body{min-height:30px; display:flex; flex-wrap:wrap}

  .pending-row{
    display:flex; align-items:center; gap:8px;
    padding:6px 10px; background:var(--panel2);
    border:1px solid var(--border); border-radius:5px;
    margin-bottom:6px; font-size:12.5px; font-family:var(--mono);
  }
  .pending-row .mode-tag{
    padding:1px 7px; border-radius:10px; font-size:11px;
    background:var(--border); color:var(--text);
  }
  .pending-row .mode-tag.move{background:#7c5cff; color:white}
  .pending-row .mode-tag.copy{background:var(--warn); color:#000}
  .pending-row .mode-tag.tag{background:var(--ok); color:#000}
  .pending-row .pending-x{
    margin-left:auto; background:transparent; border:0; color:var(--muted);
    cursor:pointer; font-size:16px; line-height:1; padding:0 4px;
  }
  .pending-row .pending-x:hover{color:var(--danger)}
  .pending-row.ok{border-color:var(--ok)}
  .pending-row.err{border-color:var(--danger)}

  .op-modal{
    position:fixed; inset:0; background:rgba(0,0,0,0.65);
    display:none; align-items:center; justify-content:center; z-index:2000;
  }
  .op-modal.show{display:flex}
  .op-modal-inner{
    background:var(--panel); border:1px solid var(--border);
    border-radius:8px; padding:24px; min-width:420px;
    box-shadow:0 8px 32px rgba(0,0,0,0.5);
  }
  .op-modal-title{font-size:14px; color:var(--text); text-align:center}
</style>
</head>
<body>

<header>
  <span class="dot"></span>
  <h1>BMT Vault Reorganizer</h1>
  <span class="small" style="margin-left:auto">running locally on 127.0.0.1</span>
  <button class="btn danger" style="margin-left:12px; padding:6px 14px; font-size:13px"
          onclick="shutdownServer()">Shut down</button>
</header>

<nav class="tabs">
  <button class="active" data-tab="run">Run</button>
  <button data-tab="taxonomy">Taxonomy</button>
  <button data-tab="folders">Folders</button>
</nav>

<main>

  <!-- ============================ RUN TAB ============================ -->
  <section id="tab-run" class="tab-content active">

    <div class="card">
      <label for="vault">Vault folder</label>
      <div style="display:flex; align-items:center; gap:8px">
        <input type="text" id="vault" value="{{ config.vault }}"
               placeholder="e.g. D:\bayyari\bmt" spellcheck="false" style="flex:1" />
        <span id="vault-status"></span>
      </div>
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
          <label for="cyber_folder">Domain folder name</label>
          <input type="text" id="cyber_folder" value="{{ config.cyber_folder }}" placeholder="domains" />
        </div>
        <div style="flex:0 0 auto; padding-bottom:9px">
          <label class="checkbox">
            <input type="checkbox" id="no_sidecars" {% if config.no_sidecars %}checked{% endif %} />
            <span>No PDF/DOCX sidecars</span>
          </label>
          <label class="checkbox" style="margin-top:6px">
            <input type="checkbox" id="folder_tags" {% if config.folder_tags %}checked{% endif %} />
            <span>Add folder names as tags</span>
          </label>
          <label class="checkbox" style="margin-top:6px">
            <input type="checkbox" id="suggest_folder_domains" {% if config.suggest_folder_domains %}checked{% endif %} />
            <span>Suggest domains from folders</span>
          </label>
          <label class="checkbox" style="margin-top:6px">
            <input type="checkbox" id="single_domain" {% if config.single_domain %}checked{% endif %} />
            <span>Single domain only</span>
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
        <button class="btn" onclick="stopScan()">Stop Scan</button>
      </div>
      <div class="help" style="margin-top:10px">
        <strong>Dry Run</strong> shows the topic plan without writing anything. &nbsp;
        <strong>Apply</strong> backs up your vault, then writes tags, links, MOC, and the domain folder. &nbsp;
        <strong>Clean</strong> removes everything this tool added. If folder tags are enabled, it also removes
        those slugs from <code>tags:</code>.
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
        <div class="tax-search-wrap">
          <input type="text" id="tax-search-primary" placeholder="Filter topics or keywords..."
                 oninput="filterTaxonomy('primary', this.value)" spellcheck="false" />
          <button class="tax-search-clear" onclick="clearTaxSearch('primary')" title="Clear">×</button>
        </div>
        <div id="col-primary"></div>
      </div>
      <div class="tax-col">
        <h2>
          Domains
          <button class="add-topic" onclick="addTopic('domain')">+ New Domain</button>
        </h2>
        <div class="tax-search-wrap">
          <input type="text" id="tax-search-domain" placeholder="Filter domains or keywords..."
                 oninput="filterTaxonomy('domain', this.value)" spellcheck="false" />
          <button class="tax-search-clear" onclick="clearTaxSearch('domain')" title="Clear">×</button>
        </div>
        <div id="col-domain"></div>
      </div>
    </div>
  </section>

  <!-- ============================ FOLDERS TAB ============================ -->
  <section id="tab-folders" class="tab-content">
    <div class="card">
      <label>Folder-based controls</label>
      <div class="row" style="margin-top:6px">
        <div style="flex:0 0 220px">
          <label for="folder_depth">Folder depth</label>
          <select id="folder_depth" style="width:100%; padding:9px 12px; background:var(--panel2); color:var(--text); border:1px solid var(--border); border-radius:6px;">
            <option value="top" selected>Top-level only</option>
            <option value="all">All levels</option>
          </select>
        </div>
        <div style="flex:1">
          <label>&nbsp;</label>
          <div class="btn-row" style="margin-top:0">
            <button class="btn" onclick="loadFolders()">Refresh</button>
            <button class="btn danger" onclick="removeAllFolderTags()">Remove all folder tags</button>
            <button class="btn" onclick="clearFolderRules()">Clear rules</button>
          </div>
        </div>
      </div>
      <div class="help">Manage folder-derived tags and add folder names as domains.</div>
    </div>

    <div class="card">
      <label>Detected folders</label>
      <div id="folder-list"></div>
    </div>

    <!-- Card A: Organize — scan controls -->
    <div class="card">
      <label>Organize · drag &amp; drop files into domains</label>
      <div class="row" style="margin-top:6px">
        <div style="flex:0 0 260px">
          <label for="org_folder">Domain folder name</label>
          <input type="text" id="org_folder" placeholder="domains" />
        </div>
        <div style="flex:1; padding-bottom:9px">
          <label>&nbsp;</label>
          <div class="btn-row" style="margin-top:0">
            <button class="btn primary" onclick="ORG.scan()">Scan vault</button>
            <button class="btn" onclick="ORG.resetSuggestions()">Reset to suggestions</button>
          </div>
        </div>
      </div>
      <div class="help" style="margin-top:8px">
        <span style="display:inline-flex; align-items:center; gap:5px; margin-right:14px"><span class="file-dot suggested" style="background:#7c5cff"></span> suggested</span>
        <span style="display:inline-flex; align-items:center; gap:5px; margin-right:14px"><span class="file-dot staged" style="background:#7c5cff"></span> staged</span>
        <span style="display:inline-flex; align-items:center; gap:5px"><span class="file-dot pending" style="background:#7c5cff"></span> pending operation</span>
      </div>
      <div class="help" id="org-status" style="margin-top:6px"></div>
    </div>

    <!-- Card B: files grouped by source folder -->
    <div class="card">
      <label>Files by source folder</label>
      <div id="org-files" style="max-height:300px; overflow:auto">
        <div class="empty">Click <strong>Scan vault</strong> to load files.</div>
      </div>
    </div>

    <!-- Card C: domain drop bins -->
    <div class="card">
      <label>Domains (drop targets)</label>
      <div id="org-bins" class="domain-grid">
        <div class="empty">Run a scan to load domain bins.</div>
      </div>
    </div>

    <!-- Card D: pending operations queue -->
    <div class="card">
      <label>Pending operations</label>
      <div id="org-pending"><div class="empty">No pending operations.</div></div>
      <div class="btn-row" style="margin-top:10px">
        <button class="btn primary" onclick="ORG.applyPending()" id="org-apply-btn" disabled>Apply pending (0)</button>
        <button class="btn" onclick="ORG.clearPending()">Clear</button>
      </div>
    </div>
  </section>

  <!-- Drop-action modal -->
  <div id="op-modal" class="op-modal">
    <div class="op-modal-inner">
      <div class="op-modal-title" id="op-modal-title">Drop file</div>
      <div class="btn-row" style="margin-top:14px; justify-content:center; gap:8px">
        <button class="btn primary" onclick="ORG.modalChoose('move')">Move file</button>
        <button class="btn" onclick="ORG.modalChoose('copy')">Copy file</button>
        <button class="btn" onclick="ORG.modalChoose('tag')">Tag only</button>
        <button class="btn danger" onclick="ORG.modalChoose(null)">Cancel</button>
      </div>
    </div>
  </div>

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
    if (b.dataset.tab === 'folders') loadFolders();
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
function run(mode) {
  const vault = document.getElementById('vault').value.trim();
  if (!vault) { toast('Set the vault path first', false); return; }
  if (mode === 'apply' && !confirm('Apply changes to ' + vault + '?\n\nA timestamped backup will be created first.')) return;
  if (mode === 'clean-apply' && !confirm('Remove ALL auto-generated content from ' + vault + '?\n\nA backup will be created first.')) return;

  const out = document.getElementById('output');
  out.textContent = '';
  const buttons = document.querySelectorAll('.btn-row .btn');
  buttons.forEach(b => b.disabled = true);
  out.innerHTML = '<span class="spinner"></span>Running ' + mode + '...';

  const params = new URLSearchParams({
    mode, vault,
    top_k:     document.getElementById('top_k').value,
    threshold: document.getElementById('threshold').value,
    cyber_folder: document.getElementById('cyber_folder').value.trim(),
    no_sidecars:  document.getElementById('no_sidecars').checked,
    folder_tags:  document.getElementById('folder_tags').checked,
    suggest_folder_domains: document.getElementById('suggest_folder_domains').checked,
    single_domain: document.getElementById('single_domain').checked,
  });

  out.textContent = '';
  const es = new EventSource('/api/run-stream?' + params.toString());

  es.onmessage = (e) => {
    out.textContent += e.data + '\n';
    out.scrollTop = out.scrollHeight;
  };

  es.addEventListener('done', () => {
    es.close();
    buttons.forEach(b => b.disabled = false);
  });

  es.onerror = () => {
    es.close();
    if (!out.textContent.trim()) out.textContent = 'Connection error — scan may still be running.';
    buttons.forEach(b => b.disabled = false);
  };
}

async function stopScan() {
  try {
    await fetch('/api/stop-scan', {method:'POST'});
    toast('Stop requested', true);
  } catch (e) {
    toast('Failed to request stop', false);
  }
}

async function shutdownServer() {
  if (!confirm('Stop the dashboard server?')) return;
  try {
    await fetch('/api/shutdown', {method:'POST'});
  } catch (e) { /* server closing causes fetch to throw — expected */ }
  document.body.innerHTML = '<div style="padding:40px;color:#9a9a9a;font-family:sans-serif;font-size:15px">Server stopped. You can close this tab.</div>';
}

// -------- folder controls --------
function slugifyLocal(text) {
  return text.toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'untitled';
}

async function loadFolders() {
  const vault = document.getElementById('vault').value.trim();
  if (!vault) { toast('Set the vault path first', false); return; }
  const depth = document.getElementById('folder_depth').value;
  const cyber_folder = document.getElementById('cyber_folder').value.trim();
  const r = await fetch('/api/folders?vault=' + encodeURIComponent(vault) +
                        '&depth=' + encodeURIComponent(depth) +
                        '&cyber_folder=' + encodeURIComponent(cyber_folder));
  const data = await r.json();
  if (!data.ok) { toast(data.message || 'Failed to load folders', false); return; }
  document.getElementById('folder_depth').value = data.rules.depth || depth;
  renderFolders(data.folders || []);
}

// -------- ORG: scan-preview + drag-drop file organizer --------
const ORG = {
  files: [],           // [{path, folder, primary, domains, already_in_domain}]
  domains: [],         // sorted list of all domain names
  folders: [],         // sorted source-folder names
  binFor: {},          // path -> bin name ('' if no bin)
  staged: {},          // path -> {dest, mode}
  pending: [],         // [{src, dest_folder, mode}]
  topicColors: {},
  _modal: { resolve: null, src: null, dest: null },

  hashColor(s) {
    if (this.topicColors[s]) return this.topicColors[s];
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    const hue = h % 360;
    const c = `hsl(${hue} 65% 55%)`;
    this.topicColors[s] = c;
    return c;
  },

  _vault() { return document.getElementById('vault').value.trim(); },
  _cyberFolder() {
    // Use Organize tab's folder field if set; else fall back to Run tab's value
    const v = document.getElementById('org_folder').value.trim();
    return v || document.getElementById('cyber_folder').value.trim() || 'domains';
  },

  async scan() {
    const vault = this._vault();
    if (!vault) { toast('Set the vault path first', false); return; }
    const folder = this._cyberFolder();
    const status = document.getElementById('org-status');
    status.textContent = 'Scanning...';
    try {
      const r = await fetch('/api/scan-preview?vault=' + encodeURIComponent(vault)
                            + '&cyber_folder=' + encodeURIComponent(folder));
      const d = await r.json();
      if (!d.ok) { toast(d.message || 'Scan failed', false); status.textContent = ''; return; }
      // Sync the Run tab's cyber_folder field so both stay in sync
      document.getElementById('cyber_folder').value = folder;
      this.files = d.files || [];
      this.domains = d.domains || [];
      this.folders = d.folders || [];
      this.binFor = {};
      this.staged = {};
      this.pending = [];
      // Auto-place: suggest first matching domain; or use already_in_domain
      for (const f of this.files) {
        if (f.already_in_domain) this.binFor[f.path] = f.already_in_domain;
        else if (f.domains && f.domains.length) this.binFor[f.path] = f.domains[0];
        else this.binFor[f.path] = '';
      }
      this.renderAll();
    } catch (e) {
      toast('Scan error: ' + e.message, false);
      status.textContent = '';
    }
  },

  resetSuggestions() {
    if (!this.files.length) { toast('Run a scan first', false); return; }
    this.binFor = {};
    this.staged = {};
    this.pending = [];
    for (const f of this.files) {
      if (f.already_in_domain) this.binFor[f.path] = f.already_in_domain;
      else if (f.domains && f.domains.length) this.binFor[f.path] = f.domains[0];
      else this.binFor[f.path] = '';
    }
    this.renderAll();
  },

  renderAll() {
    this.renderStatus();
    this.renderFiles();
    this.renderBins();
    this.renderPending();
  },

  renderStatus() {
    const total = this.files.length;
    const suggested = this.files.filter(f => !f.already_in_domain && this.binFor[f.path]).length;
    const staged = Object.keys(this.staged).length;
    document.getElementById('org-status').textContent =
      `${total} files scanned · ${suggested} suggested · ${staged} staged · ${this.pending.length} pending`;
  },

  renderFiles() {
    const container = document.getElementById('org-files');
    if (!this.files.length) {
      container.innerHTML = '<div class="empty">No files found in vault.</div>';
      return;
    }
    const byFolder = {};
    for (const f of this.files) (byFolder[f.folder] = byFolder[f.folder] || []).push(f);
    const folders = Object.keys(byFolder).sort((a,b) => a.localeCompare(b));
    container.innerHTML = folders.map(folder => {
      const items = byFolder[folder];
      const dots = items.map(f => this._dotHTML(f)).join('');
      return `
        <div class="folder-group" data-folder="${escape(folder)}">
          <div class="folder-group-head" onclick="this.parentNode.classList.toggle('collapsed')">
            <span>▾</span><span>${escape(folder)}</span><span style="opacity:0.6">(${items.length})</span>
          </div>
          <div class="folder-group-body">${dots}</div>
        </div>`;
    }).join('');
    this._wireDragSources();
  },

  renderBins() {
    const container = document.getElementById('org-bins');
    if (!this.domains.length) {
      container.innerHTML = '<div class="empty">No domains in taxonomy.</div>';
      return;
    }
    // group files by current bin assignment
    const inBin = {};
    for (const d of this.domains) inBin[d] = [];
    for (const f of this.files) {
      const b = this.binFor[f.path];
      if (b && inBin[b]) inBin[b].push(f);
    }
    container.innerHTML = this.domains.map(d => {
      const dots = inBin[d].map(f => this._dotHTML(f)).join('') || '<span class="empty">drop here</span>';
      return `
        <div class="domain-bin" data-domain="${escape(d)}"
             ondragover="ORG.onDragOver(event)"
             ondragleave="ORG.onDragLeave(event)"
             ondrop="ORG.onDrop(event, '${escape(d).replace(/'/g, "\\'")}')">
          <div class="domain-bin-name">${escape(d)}</div>
          <div class="domain-bin-body">${dots}</div>
        </div>`;
    }).join('');
    this._wireDragSources();
  },

  _dotHTML(f) {
    let cls = 'file-dot';
    if (this.staged[f.path])             cls += ' pending';
    else if (f.already_in_domain)         cls += ' placed';
    else if (this.binFor[f.path])         cls += ' suggested';
    const color = this.hashColor(f.primary || 'Uncategorized');
    const tip = `${f.path}\nPrimary: ${f.primary}\nDomains: ${(f.domains||[]).join(', ') || 'none'}` +
                (f.already_in_domain ? `\nAlready placed in: ${f.already_in_domain}` : '');
    return `<span class="${cls}" style="background:${color}"
             draggable="true"
             data-path="${escape(f.path)}"
             title="${escape(tip)}"></span>`;
  },

  _wireDragSources() {
    document.querySelectorAll('.file-dot[draggable=true]').forEach(el => {
      el.ondragstart = (e) => {
        e.dataTransfer.setData('text/plain', el.dataset.path);
        e.dataTransfer.effectAllowed = 'copyMove';
      };
    });
  },

  onDragOver(e) { e.preventDefault(); e.currentTarget.classList.add('dragover'); },
  onDragLeave(e) { e.currentTarget.classList.remove('dragover'); },

  async onDrop(e, domain) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
    const src = e.dataTransfer.getData('text/plain');
    if (!src) return;
    const file = this.files.find(f => f.path === src);
    if (!file) return;
    // open modal — user picks Move / Copy / Tag / Cancel
    const mode = await this.askMode(src, domain);
    if (!mode) return;
    this.stage(src, domain, mode);
  },

  askMode(src, domain) {
    const modal = document.getElementById('op-modal');
    const filename = src.split('/').pop();
    document.getElementById('op-modal-title').innerHTML =
      `Drop <strong>${escape(filename)}</strong> into <strong>${escape(domain)}</strong>`;
    modal.classList.add('show');
    this._modal.src = src; this._modal.dest = domain;
    return new Promise(resolve => { this._modal.resolve = resolve; });
  },

  modalChoose(mode) {
    document.getElementById('op-modal').classList.remove('show');
    if (this._modal.resolve) this._modal.resolve(mode);
    this._modal.resolve = null;
  },

  stage(src, domain, mode) {
    // remove any prior pending op for the same file
    this.pending = this.pending.filter(o => o.src !== src);
    this.pending.push({ src, dest_folder: domain, mode });
    this.staged[src] = { dest: domain, mode };
    this.binFor[src] = domain;
    this.renderAll();
  },

  unstage(src) {
    this.pending = this.pending.filter(o => o.src !== src);
    delete this.staged[src];
    // Restore the previous suggestion
    const f = this.files.find(x => x.path === src);
    if (f) {
      if (f.already_in_domain) this.binFor[src] = f.already_in_domain;
      else if (f.domains && f.domains.length) this.binFor[src] = f.domains[0];
      else this.binFor[src] = '';
    }
    this.renderAll();
  },

  clearPending() {
    if (!this.pending.length) return;
    for (const op of this.pending) {
      delete this.staged[op.src];
      const f = this.files.find(x => x.path === op.src);
      if (f) {
        if (f.already_in_domain) this.binFor[op.src] = f.already_in_domain;
        else if (f.domains && f.domains.length) this.binFor[op.src] = f.domains[0];
        else this.binFor[op.src] = '';
      }
    }
    this.pending = [];
    this.renderAll();
  },

  renderPending() {
    const container = document.getElementById('org-pending');
    const btn = document.getElementById('org-apply-btn');
    if (!this.pending.length) {
      container.innerHTML = '<div class="empty">No pending operations.</div>';
      btn.disabled = true;
      btn.textContent = 'Apply pending (0)';
      return;
    }
    container.innerHTML = this.pending.map((o, i) => `
      <div class="pending-row" data-i="${i}">
        <span class="mode-tag ${o.mode}">${o.mode}</span>
        <span>${escape(o.src.split('/').pop())}</span>
        <span style="opacity:0.6">→</span>
        <span>${escape(o.dest_folder)}</span>
        <button class="pending-x" onclick="ORG.unstage('${escape(o.src).replace(/'/g, "\\'")}')" title="Remove">×</button>
      </div>`).join('');
    btn.disabled = false;
    btn.textContent = `Apply pending (${this.pending.length})`;
  },

  async applyPending() {
    if (!this.pending.length) return;
    const vault = this._vault();
    if (!vault) { toast('Set the vault path first', false); return; }
    if (!confirm(`Apply ${this.pending.length} operation(s)?\nA backup will be created if any files move/copy.`)) return;
    const btn = document.getElementById('org-apply-btn');
    btn.disabled = true; btn.textContent = 'Applying...';
    try {
      const r = await fetch('/api/file-ops-batch', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          vault,
          cyber_folder: this._cyberFolder(),
          operations: this.pending,
        })
      });
      const d = await r.json();
      if (!d.ok) { toast(d.message || 'Batch failed', false); return; }
      toast(`Applied ${d.applied}, ${d.failed} failed`, d.failed === 0);
      // Mark rows visually
      const rows = document.querySelectorAll('#org-pending .pending-row');
      (d.results || []).forEach((res, i) => {
        if (rows[i]) rows[i].classList.add(res.ok ? 'ok' : 'err');
        if (rows[i] && !res.ok) {
          rows[i].title = res.message || 'failed';
        }
      });
      // Re-scan to pick up the new vault state
      setTimeout(() => this.scan(), 600);
    } catch (e) {
      toast('Apply error: ' + e.message, false);
    } finally {
      btn.disabled = false;
    }
  },
};

// Initialize the Organize folder field with the Run tab's value on load
(function syncOrgFolder() {
  const orgFolder = document.getElementById('org_folder');
  const cyberFolder = document.getElementById('cyber_folder');
  if (orgFolder && cyberFolder && !orgFolder.value) {
    orgFolder.value = cyberFolder.value || 'domains';
  }
  // keep them in sync — editing one updates the other
  if (orgFolder) orgFolder.addEventListener('input', () => { cyberFolder.value = orgFolder.value; });
  if (cyberFolder) cyberFolder.addEventListener('input', () => { if (orgFolder) orgFolder.value = cyberFolder.value; });
})();

document.getElementById('folder_depth').addEventListener('change', async (e) => {
  const depth = e.target.value;
  const r = await fetch('/api/folder-rules', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'set-depth', depth})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadFolders();
});

function renderFolders(items) {
  const container = document.getElementById('folder-list');
  if (!items.length) {
    container.innerHTML = '<div class="empty">No folders detected.</div>';
    return;
  }
  container.innerHTML = items.map(it => `
    <div class="folder-row">
      <div class="folder-name">${escape(it.name)}</div>
      <div class="folder-count">${it.count} file(s)</div>
      <div class="folder-actions">
        <button class="btn" onclick="addFolderDomain('${escape(it.name)}')">Add domain</button>
        <button class="btn" onclick="excludeFolder('${escape(it.name)}')">Exclude</button>
        <button class="btn" onclick="renameFolderTag('${escape(it.name)}')">Rename tag</button>
        <button class="btn danger" onclick="removeFolderTag('${escape(it.name)}')">Remove tag</button>
      </div>
    </div>
  `).join('');
}

document.getElementById('domain_folder').addEventListener('change', (e) => {
  document.getElementById('domain_name').value = e.target.value;
});

async function addFolderDomain(name) {
  const r = await fetch('/api/folder-domains', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({names:[name]})
  });
  const data = await r.json();
  toast(data.message, data.ok);
}

async function excludeFolder(name) {
  const r = await fetch('/api/folder-rules', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'add-exclude', name})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadFolders();
}

async function renameFolderTag(name) {
  const newName = prompt('Rename folder tag for: ' + name + '\nNew tag name:');
  if (!newName || !newName.trim()) return;
  const r = await fetch('/api/folder-rules', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'rename', name, new:newName.trim()})
  });
  const data = await r.json();
  toast(data.message, data.ok);
}

async function removeFolderTag(name) {
  const vault = document.getElementById('vault').value.trim();
  if (!vault) { toast('Set the vault path first', false); return; }
  const cyber_folder = document.getElementById('cyber_folder').value.trim();
  const slug = slugifyLocal(name);
  const r = await fetch('/api/remove-folder-tags', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({vault, cyber_folder, slugs:[slug]})
  });
  const data = await r.json();
  if (data.ok) { toast('Folder tag removed', true); }
  else { toast(data.message || 'Remove failed', false); }
}

async function removeAllFolderTags() {
  const vault = document.getElementById('vault').value.trim();
  if (!vault) { toast('Set the vault path first', false); return; }
  if (!confirm('Remove all folder-based tags from notes? A backup will be created.')) return;
  const cyber_folder = document.getElementById('cyber_folder').value.trim();
  const r = await fetch('/api/remove-folder-tags', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({vault, cyber_folder, mode:'all'})
  });
  const data = await r.json();
  if (data.ok) { toast('Folder tags removed', true); }
  else { toast(data.message || 'Remove failed', false); }
}

async function clearFolderRules() {
  if (!confirm('Clear all folder exclude and rename rules?')) return;
  const r = await fetch('/api/folder-rules', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({action:'clear'})
  });
  const data = await r.json();
  toast(data.message, data.ok);
  if (data.ok) loadFolders();
}

// -------- taxonomy editor --------
async function loadTaxonomy() {
  const r = await fetch('/api/taxonomy');
  const data = await r.json();
  renderColumn('primary', data.primary_topics, document.getElementById('col-primary'));
  renderColumn('domain',  data.cyber_domains,  document.getElementById('col-domain'));
  // re-apply any active search filter after re-render
  filterTaxonomy('primary', document.getElementById('tax-search-primary').value);
  filterTaxonomy('domain',  document.getElementById('tax-search-domain').value);
}

function filterTaxonomy(kind, query) {
  const q = query.trim().toLowerCase();
  document.getElementById('col-' + kind).querySelectorAll('.topic-card').forEach(card => {
    if (!q) { card.classList.remove('hidden'); return; }
    const name = (card.querySelector('.topic-name') || {}).textContent || '';
    const kws  = Array.from(card.querySelectorAll('.chip')).map(c => c.dataset.kw || '');
    const hay  = [name, ...kws].join(' ').toLowerCase();
    card.classList.toggle('hidden', !hay.includes(q));
  });
}

function clearTaxSearch(kind) {
  document.getElementById('tax-search-' + kind).value = '';
  filterTaxonomy(kind, '');
}

// -------- vault path validation --------
let _vaultCheckTimer = null;
function scheduleVaultCheck() {
  clearTimeout(_vaultCheckTimer);
  _vaultCheckTimer = setTimeout(checkVault, 600);
}
async function checkVault() {
  const vault = document.getElementById('vault').value.trim();
  const ind = document.getElementById('vault-status');
  if (!vault) { ind.textContent = ''; ind.className = ''; return; }
  ind.textContent = '…'; ind.className = 'checking';
  try {
    const r = await fetch('/api/check-vault?vault=' + encodeURIComponent(vault));
    const d = await r.json();
    if (d.ok) { ind.textContent = '✓'; ind.className = 'ok'; ind.title = 'Path found'; }
    else if (d.exists) { ind.textContent = '✗'; ind.className = 'err'; ind.title = 'Path exists but is not a folder'; }
    else { ind.textContent = '✗'; ind.className = 'err'; ind.title = 'Path not found'; }
  } catch (e) { ind.textContent = '?'; ind.className = 'err'; ind.title = 'Check failed'; }
}
document.getElementById('vault').addEventListener('input', scheduleVaultCheck);

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
          <span class="chip" data-kw="${escape(kw)}">${escape(kw)}
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

let _cancellingName = false;
function editName(el) { el.contentEditable = true; el.focus(); selectAll(el); }
function selectAll(el) {
  const r = document.createRange(); r.selectNodeContents(el);
  const s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
}
function nameKey(e, el) {
  if (e.key === 'Enter') { e.preventDefault(); el.blur(); }
  if (e.key === 'Escape') {
    _cancellingName = true;
    el.textContent = el.dataset.orig;
    el.blur();
  }
}
async function commitName(el, kind) {
  if (_cancellingName) {
    _cancellingName = false;
    el.contentEditable = false;
    el.textContent = el.dataset.orig;
    return;
  }
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
  const label = kind === 'primary' ? 'primary topic' : 'domain';
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

// -------- page load --------
checkVault();
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
    app.run(host='127.0.0.1', port=5050, debug=False, use_reloader=False, threaded=True)


if __name__ == '__main__':
    main()
