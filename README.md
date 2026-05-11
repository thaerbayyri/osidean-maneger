# BMT Vault Reorganizer

Organize your Obsidian vault using a keyword taxonomy. Classifies notes, adds tags, builds MOCs, and manages cyber-security domains — all locally.

---

## Install

```bash
pip install scikit-learn numpy pypdf python-docx flask
```

---

## Run the Dashboard

```bash
python dashboard.py
```

Opens **http://127.0.0.1:5050** automatically.

---

## Using the Dashboard

### Run tab
1. Paste your vault path in **Vault folder** — a ✓ confirms the path exists.
2. Adjust **Top-K**, **Threshold**, and options as needed.
3. Click **Dry Run** to preview, then **Apply Changes** to write (a backup is created automatically).
4. Use **Clean (preview / apply)** to remove everything the tool added.
5. **Stop Scan** cancels a running operation. **Shut down** stops the server.

### Taxonomy tab
- Search topics or keywords using the filter box above each column.
- Click a topic name to rename it (Enter to save, Escape to cancel).
- Add/remove keywords with the chips below each topic.
- Use **+ New Topic / + New Domain** to create entries.

### Folders tab
- **Refresh** to detect vault folders and their file counts.
- **Add domain** — register a folder as a cyber domain.
- **Exclude** — skip a folder from tag generation.
- **Rename tag / Remove tag** — control folder-derived tag slugs.
- **Clear rules** — reset all exclude/rename rules.
- **Remove all folder tags** — strip folder tags from every note.

---

## CLI (optional)

```bash
# Preview only (no writes)
python obsidian_reorganize.py "D:\path\to\vault"

# Write changes (creates backup first)
python obsidian_reorganize.py "D:\path\to\vault" --apply

# Remove everything the tool added
python obsidian_reorganize.py "D:\path\to\vault" --clean --apply
```

---

## Notes

- Everything runs locally — nothing leaves your machine.
- `taxonomy.json` is auto-created on first run; edit it to tune keywords.
- Every write operation backs up your vault before touching anything.
