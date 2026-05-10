# Obsidian Vault Reorganizer

A local toolset for organizing an Obsidian vault using a keyword taxonomy. It can:
- Classify notes into a single primary topic and multiple domains.
- Add frontmatter tags and a Related section to notes.
- Generate MOCs (Map of Content) and domain folders.
- Handle PDF/DOCX files via sidecar index notes.
- Provide a lightweight local dashboard for running and editing taxonomy.

## Project files
- `obsidian_reorganize.py`: Taxonomy Edition v2 (CLI + taxonomy.json support).
- `obsidian_reorganize2.py`: Older taxonomy CLI (kept for reference).
- `dashboard.py`: Local Flask UI for the v2 reorganizer.
- `taxonomy.json`: Editable taxonomy (written on first run or via reset).
- `dashboard_config.json`: Saved UI settings.

## Requirements
- Python 3.9+ recommended.
- Dependencies:
  - `scikit-learn`
  - `numpy`
  - `pypdf` (or `PyPDF2`)
  - `python-docx`
  - `flask` (dashboard only)

Install:
```bash
pip install scikit-learn numpy pypdf python-docx flask
```

## CLI usage (v2)
Dry-run by default. Use `--apply` to write changes.

```bash
python obsidian_reorganize.py "D:\\path\\to\\vault"
python obsidian_reorganize.py "D:\\path\\to\\vault" --apply
python obsidian_reorganize.py "D:\\path\\to\\vault" --clean
python obsidian_reorganize.py "D:\\path\\to\\vault" --clean --apply
python obsidian_reorganize.py --list-taxonomy
python obsidian_reorganize.py --reset-taxonomy
```

## Dashboard usage
The dashboard runs locally and calls the v2 script under the hood.

```bash
python dashboard.py
```

Open http://127.0.0.1:5050 and set:
- Vault folder
- Top-K related notes
- Similarity threshold
- Cyber domains folder name

## How it works (high level)
1. Reads each note and scores keywords against the taxonomy.
2. Assigns one primary topic and any matching cyber domains.
3. Adds tags/domains to frontmatter and appends an auto-managed block.
4. Builds `MOC.md` plus `cyber domains/Cyber Domains MOC.md`.
5. For PDF/DOCX, writes a sidecar `.index.md` note.

## Notes
- The tool is safe by default: dry-run and idempotent updates.
- `taxonomy.json` is the source of truth once created; edit it to tune keywords.
- Backups are created on apply in the v1 script; v2 focuses on taxonomy + sidecars.

## License
Add your license here.
