# BMT Vault Reorganizer

Organize your Obsidian vault using a keyword taxonomy. Classifies notes, adds tags, builds MOCs, and lets you **drag and drop files into domains** with a visual organizer — all locally.

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
- **Add domain** — register a folder as a domain.
- **Exclude** — skip a folder from tag generation.
- **Rename tag / Remove tag** — control folder-derived tag slugs.
- **Clear rules** — reset all exclude/rename rules.
- **Remove all folder tags** — strip folder tags from every note.

### Organize section (drag & drop)

Below the folder controls, the **Organize** section lets you visually place files into domains:

1. Set the **Domain folder name** (where domain subfolders live, e.g. `domains`).
2. Click **Scan vault** — every file appears as a colored dot grouped by source folder. The system **suggests** a domain for each file (dashed border).
3. **Drag a dot onto a domain bin**. A small dialog appears:
   - **Move file** — physically moves the file into `domains/<Domain>/`
   - **Copy file** — leaves the original, places a copy in the domain
   - **Tag only** — adds the domain to the file's frontmatter, no file movement
4. Staged operations stack in the **Pending operations** queue. Remove any with `×`.
5. Click **Apply pending** to run the batch. A single timestamped backup is created automatically if any file is moved or copied.
6. **Reset to suggestions** discards your staged changes and restores the auto-suggested layout.

Dot colors are hashed from each file's primary topic. Hover a dot to see its full path and classification.

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
- Every write operation (Apply, Clean, drag-drop Move/Copy batches) backs up your vault to `<vault>-backup-<timestamp>` first.
- The Organize section detects files already placed under a domain folder and shows them with a solid green border — re-scanning is safe.
