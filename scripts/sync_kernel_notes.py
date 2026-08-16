#!/usr/bin/env python3
"""
Sync Obsidian kernel-exploitation notes into the "Kernel Exploitation Notes"
section of the site (blogs/notes/kernel-exploitation/).

Usage:
    python3 scripts/sync_kernel_notes.py
    python3 scripts/sync_kernel_notes.py --vault "/path/to/kpw_notes" --dry-run
    python3 scripts/sync_kernel_notes.py --prune   # also delete pages whose source note is gone

What it does, every run:
  1. Scans every category subfolder in the vault (each top-level folder =
     one category, e.g. "Heap Spraying"), skipping `.obsidian`, any file
     named "_Template.md", and any file with "MOC" in its name.
  2. Within a category, a note can either sit loose directly in that
     folder, or be grouped inside one level of subdirectory (e.g.
     "Internals/MM/Buddy Allocator.md"). A subdirectory like that becomes
     a subgroup: its notes publish under <category>/<subgroup>/<note>/
     instead of <category>/<note>/, and it renders as its own nested
     branch in both the floating nav and the index tree diagram. This is
     entirely optional — a category with no subdirectories behaves exactly
     as before. Only one level of nesting is supported (a subdirectory
     inside a subdirectory is not walked).
  3. For each note: strips YAML frontmatter, resolves [[wiki-links]] and
     `related:` entries against every other note in the vault, copies
     any ![[embedded images]] into that category's assets/ folder,
     de-links local filesystem paths (they'd be dead links once published),
     extracts a trailing/leading "#tag #tag2" line into tag pills, and
     writes out a Jekyll page with a metadata panel built from whatever
     frontmatter fields are present.
  4. Regenerates the shared floating nav include (grouped by category,
     with subgroups nested underneath their category) and the
     overview/index page — an intro paragraph, a live search box, then a
     tree view of every category/subgroup/note, each note name a real
     link. The search box's index (title/breadcrumb/href per note) is
     rebuilt from scratch every run, so it never drifts from the tree.

The intro paragraph lives in its own file, blogs/notes/kernel-exploitation/
_intro.md, created with a default the first time this runs. Edit that
file directly whenever you want — reruns read it back in and never
overwrite it, so your wording is never clobbered by a resync.

An empty source file (0 bytes) is synced as a real page with a
"Note not written yet — to be added." placeholder, so you can create a
stub file in Obsidian and have the site pick it up immediately, then
fill it in later without needing to run anything else.

Categories/notes already published keep their existing slugs (see the
override dicts below) even if the auto-slugified name would differ, so
re-running this never changes a URL that's already live. Brand new
categories/notes get a slug auto-generated from their name/filename.
"""

import argparse
import json
import os
import re
import shutil
import sys

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml (or run via `bundle exec ruby` env if that has it)")

# ---------------------------------------------------------------------------
# Defaults — override via CLI flags if your paths differ.
# ---------------------------------------------------------------------------
DEFAULT_VAULT = os.path.expanduser("~/Documents/kpwn/notes/kpw_notes")
DEFAULT_SITE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_URL = "/blogs/notes/kernel-exploitation/"

SKIP_DIR_NAMES = {".obsidian"}
SKIP_FILE_PATTERNS = [re.compile(r"MOC", re.IGNORECASE), re.compile(r"^_Template$", re.IGNORECASE)]

# Slugs/titles already live on the site — keep these stable across reruns.
CATEGORY_SLUG_OVERRIDES = {
    "internals": "internals",
    "heap spraying": "heap-spraying",
    "krop": "krop",
    "page spraying(cross cache attacks)": "page-spraying",
    "targets": "targets",
}
CATEGORY_TITLE_OVERRIDES = {
    "internals": "Internals",
    "heap spraying": "Heap Spraying",
    "krop": "KROP",
    "page spraying(cross cache attacks)": "Page Spraying (Cross-Cache Attacks)",
    "targets": "Targets",
}
# key = normalized (lowercased) filename stem -> slug/title override
NOTE_SLUG_OVERRIDES = {
    "linux slub allocator": "slub-allocator",
    "how google mitigates cross cache attacks": "cross-cache-mitigations",
}
NOTE_TITLE_OVERRIDES = {
    "how google mitigates cross cache attacks": "How Google Mitigates Cross-Cache Attacks?",
    "ropbot-angrop": "RopBot / Angrop",
    "how syscalls work": "How Syscalls Work?",
    "kernel module internals": "Kernel Module Internals",
}

# One level of subdirectory inside a category folder (e.g. "Internals/MM")
# becomes a subgroup. key = normalized (lowercased) subdirectory name.
SUBCATEGORY_SLUG_OVERRIDES = {}
SUBCATEGORY_TITLE_OVERRIDES = {}

# Category display order — known ones first, any new category appended
# alphabetically after these.
CATEGORY_ORDER = ["internals", "heap-spraying", "krop", "page-spraying", "targets", "misc"]

TAG_LINE_RE = re.compile(r"^#[\w-]+(?:\s+#[\w-]+)*\s*$")
WIKILINK_RE = re.compile(r"\[\[([^\]]+)\]\]")
EMBED_RE = re.compile(r"!\[\[([^\]]+)\]\]")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")

# The site has no MathJax/KaTeX, so $$...$$ LaTeX (Obsidian renders this
# natively) would show up as raw unrendered text if copied through as-is.
# Convert it to a plain code block instead, translating the handful of
# LaTeX macros that show up in these notes (arrow chains like a -> b -> c).
LATEX_BLOCK_RE = re.compile(r"\$\$(.+?)\$\$", re.DOTALL)
LATEX_MACRO_SUBS = [
    (re.compile(r"\\rightarrow"), "->"),
    (re.compile(r"\\longrightarrow"), "->"),
    (re.compile(r"\\to\b"), "->"),
    (re.compile(r"\\leftarrow"), "<-"),
    (re.compile(r"\\times"), "*"),
    (re.compile(r"\\cdot"), "*"),
    (re.compile(r"\\neq"), "!="),
    (re.compile(r"\\leq"), "<="),
    (re.compile(r"\\geq"), ">="),
]


def slugify(name):
    s = name.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")


def norm(s):
    s = s.strip().strip("?").strip('"')
    s = s.split("/")[-1]
    return s.strip().lower()


def should_skip_file(filename):
    if not filename.lower().endswith(".md"):
        return True
    stem = filename[:-3]
    return any(p.search(stem) for p in SKIP_FILE_PATTERNS)


def _note_tuple(fname):
    stem = fname[:-3]
    nkey = stem.strip().strip("?").strip().lower()
    note_slug = NOTE_SLUG_OVERRIDES.get(nkey, slugify(stem))
    title = NOTE_TITLE_OVERRIDES.get(nkey, stem)
    return (fname, note_slug, title)


def discover_vault(vault_root):
    """Returns [(cat_slug, cat_title, cat_dir_name, [item, ...]), ...]

    Each item is one of:
      ("note", src_name, note_slug, title)                        — a loose note
      ("group", sub_slug, sub_title, sub_dir_name, [(src_name, note_slug, title), ...])
                                                                    — one level of subdirectory
    """
    categories = []

    # Notes sitting directly in the vault root (not inside any category
    # subfolder) get grouped into a synthetic "Misc" category. cat_dir_name
    # is "" for this one, meaning the source path is vault_root itself.
    # (The vault root itself is not scanned for sub-subdirectories — nesting
    # only applies inside a real category folder.)
    root_notes = []
    for fname in sorted(os.listdir(vault_root)):
        full = os.path.join(vault_root, fname)
        if not os.path.isfile(full) or should_skip_file(fname):
            continue
        root_notes.append(("note",) + _note_tuple(fname))
    if root_notes:
        key = "misc"
        cat_slug = CATEGORY_SLUG_OVERRIDES.get(key, "misc")
        cat_title = CATEGORY_TITLE_OVERRIDES.get(key, "Misc")
        categories.append((cat_slug, cat_title, "", root_notes))

    for entry in sorted(os.listdir(vault_root)):
        full = os.path.join(vault_root, entry)
        if not os.path.isdir(full) or entry in SKIP_DIR_NAMES or entry.startswith("."):
            continue
        key = entry.strip().lower()
        cat_slug = CATEGORY_SLUG_OVERRIDES.get(key, slugify(entry))
        cat_title = CATEGORY_TITLE_OVERRIDES.get(key, entry)

        items = []
        for sub_entry in sorted(os.listdir(full)):
            sub_full = os.path.join(full, sub_entry)
            if os.path.isdir(sub_full):
                if sub_entry in SKIP_DIR_NAMES or sub_entry.startswith("."):
                    continue
                sub_key = sub_entry.strip().lower()
                sub_slug = SUBCATEGORY_SLUG_OVERRIDES.get(sub_key, slugify(sub_entry))
                sub_title = SUBCATEGORY_TITLE_OVERRIDES.get(sub_key, sub_entry)
                group_notes = []
                for fname in sorted(os.listdir(sub_full)):
                    if not os.path.isfile(os.path.join(sub_full, fname)) or should_skip_file(fname):
                        continue
                    group_notes.append(_note_tuple(fname))
                if group_notes:
                    items.append(("group", sub_slug, sub_title, sub_entry, group_notes))
            else:
                if not os.path.isfile(sub_full) or should_skip_file(sub_entry):
                    continue
                items.append(("note",) + _note_tuple(sub_entry))

        if items:
            categories.append((cat_slug, cat_title, entry, items))

    categories.sort(key=lambda c: (CATEGORY_ORDER.index(c[0]) if c[0] in CATEGORY_ORDER else 999, c[0]))
    return categories


def flatten_items(cat_title, items):
    """Yield (rel_dir_parts, src_name, note_slug, title, note_path, breadcrumb)
    for every note in a category's items list — rel_dir_parts are the
    source-side path components under the category dir (e.g. [] for a loose
    note, ["MM"] for one grouped under a "MM" subdirectory), note_path is the
    output/URL path fragment relative to the category (e.g. "buddy-allocator"
    or "mm/buddy-allocator"), and breadcrumb is the human-readable category
    (plus subgroup, if any) e.g. "Internals" or "Internals / MM"."""
    for item in items:
        if item[0] == "note":
            _, src_name, note_slug, title = item
            yield [], src_name, note_slug, title, note_slug, cat_title
        else:
            _, sub_slug, sub_title, sub_dir, group_notes = item
            breadcrumb = "{} / {}".format(cat_title, sub_title)
            for src_name, note_slug, title in group_notes:
                yield [sub_dir], src_name, note_slug, title, sub_slug + "/" + note_slug, breadcrumb


def build_lookup(categories):
    lookup = {}
    for cat_slug, cat_title, cat_dir, items in categories:
        for rel_parts, src_name, note_slug, title, note_path, breadcrumb in flatten_items(cat_title, items):
            stem = src_name[:-3]
            for alias in {title, stem, title.rstrip("?")}:
                lookup[norm(alias)] = (cat_slug, note_path, title)
    return lookup


def split_frontmatter(raw):
    # Require a literal leading "---" (only a BOM may precede it) — a stray
    # leading blank/tab before a mid-document "---" horizontal rule must
    # NOT be misread as the start of frontmatter, or real content between
    # the two gets silently swallowed as "YAML".
    stripped = raw.lstrip("﻿")
    if not stripped.startswith("---"):
        return {}, raw
    parts = stripped.split("\n", 1)
    rest = parts[1] if len(parts) > 1 else ""
    end_match = re.search(r"\n---\s*\n", rest)
    if not end_match:
        return {}, raw
    fm_text = rest[: end_match.start()]
    body = rest[end_match.end():]
    try:
        fm = yaml.safe_load(fm_text) or {}
    except yaml.YAMLError:
        fm = {}
    if not isinstance(fm, dict):
        fm = {}
    return fm, body


def extract_tags(body):
    lines = body.strip("\n").split("\n")
    tags = []
    scan_idx = list(range(min(3, len(lines)))) + list(range(max(0, len(lines) - 3), len(lines)))
    for idx in sorted(set(scan_idx)):
        if TAG_LINE_RE.match(lines[idx].strip()):
            tags = lines[idx].strip().split()
            del lines[idx]
            break
    tags = [t.lstrip("#") for t in tags]
    return tags, "\n".join(lines).strip("\n")


def as_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def render_meta_html(fm, lookup, cur_cat, cur_slug):
    rows = []
    skip_keys = {"category", "technique", "related", "summary"}
    for key, val in fm.items():
        if key in skip_keys:
            continue
        vals = as_list(val)
        if not vals:
            continue
        label = key.replace("_", " ").replace("-", " ").title()
        chips = "".join('<span class="note-meta-chip">{}</span>'.format(v) for v in vals)
        rows.append(
            '<div class="note-meta-row"><span class="note-meta-key">{}</span>'
            '<span class="note-meta-val">{}</span></div>'.format(label, chips)
        )

    related_links = []
    for r in as_list(fm.get("related")):
        r_clean = r.strip().strip('"').lstrip("[").rstrip("]").strip()
        if not r_clean:
            continue
        resolved = lookup.get(norm(r_clean))
        if resolved:
            cat_slug, note_slug, title = resolved
            if cat_slug == cur_cat and note_slug == cur_slug:
                continue
            related_links.append(
                '<a class="note-meta-chip note-meta-link" href="{}{}/{}/">{}</a>'.format(
                    BASE_URL, cat_slug, note_slug, title
                )
            )
    if related_links:
        rows.append(
            '<div class="note-meta-row"><span class="note-meta-key">Related</span>'
            '<span class="note-meta-val">{}</span></div>'.format("".join(related_links))
        )

    if not rows:
        return ""
    return '<div class="note-meta">{}</div>\n'.format("\n".join(rows))


def convert_latex(text):
    def sub(m):
        inner = m.group(1).strip()
        for pat, repl in LATEX_MACRO_SUBS:
            inner = pat.sub(repl, inner)
        inner = re.sub(r"\s+", " ", inner).strip()
        inner = re.sub(r"\s*(->|<-)\s*", r"\1", inner)
        return "```c\n{}\n```".format(inner)
    return LATEX_BLOCK_RE.sub(sub, text)


def convert_wikilinks(text, lookup):
    def sub(m):
        target = m.group(1).strip()
        resolved = lookup.get(norm(target))
        if not resolved:
            return target
        cat_slug, note_slug, title = resolved
        return "[{}]({}{}/{}/)".format(target, BASE_URL, cat_slug, note_slug)
    return WIKILINK_RE.sub(sub, text)


def convert_local_links(text):
    def sub(m):
        label, url = m.group(1), m.group(2)
        if url.startswith(("http://", "https://", "/blogs/", "#", "mailto:")):
            return m.group(0)
        return "`{}`".format(label)
    return MD_LINK_RE.sub(sub, text)


MD_STRIP_RE = re.compile(r"```[\w+-]*|`|[*_>#]|\[|\]|\(|\)")
HTML_TAG_RE = re.compile(r"<[^>]+>")


def plain_search_text(fm, tags, body):
    """Flatten frontmatter values + tags + body into one plain-text blob for
    substring search — doesn't need to read well, just needs every word/token
    that appears in the note (including things like 'kmalloc-1024' sitting
    inside a code block or a frontmatter `slab:` list) to survive."""
    parts = []
    for val in fm.values():
        parts.extend(as_list(val))
    parts.extend(tags)
    text = HTML_TAG_RE.sub(" ", body)
    text = MD_STRIP_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    parts.append(text)
    return " ".join(parts)


def process_note(src_path, cat_slug, note_slug, title, vault_root, lookup, out_assets_dir):
    with open(src_path, encoding="utf-8") as f:
        raw = f.read()

    if raw.strip() == "":
        return {"tags": [], "meta_html": "", "body": "*Note not written yet — to be added.*",
                "search_text": "", "is_empty": True}

    fm, body = split_frontmatter(raw)
    body = body.strip("\n")
    tags, body = extract_tags(body)
    body = convert_latex(body)

    src_dir = os.path.dirname(src_path)

    def embed_sub(m):
        fname = m.group(1).strip()
        candidates = [os.path.join(src_dir, fname), os.path.join(vault_root, fname)]
        src_img = next((c for c in candidates if os.path.exists(c)), None)
        safe_name = re.sub(r"[^a-zA-Z0-9.]+", "-", fname).strip("-").lower()
        if src_img:
            os.makedirs(out_assets_dir, exist_ok=True)
            shutil.copyfile(src_img, os.path.join(out_assets_dir, safe_name))
        return '<img class="note-img" src="{{{{ \'{}{}/assets/{}\' | relative_url }}}}" alt="screenshot" />'.format(
            BASE_URL, cat_slug, safe_name
        )

    body = EMBED_RE.sub(embed_sub, body)
    body = convert_wikilinks(body, lookup)
    body = convert_local_links(body)
    meta_html = render_meta_html(fm, lookup, cat_slug, note_slug)
    search_text = plain_search_text(fm, tags, body)

    return {"tags": tags, "meta_html": meta_html, "body": body, "search_text": search_text, "is_empty": False}


PAGE_TEMPLATE = """---
layout: default
title: "{title} — Kernel Exploitation Notes"
description: "{description}"
og_description: "{description}"
og_type: "article"
keywords: "kernel exploitation, linux kernel, {slug_keywords}, zoozoo-sec"
permalink: {permalink}
note_id: {cat_slug}/{note_slug}
---

<link rel="stylesheet" href="{{{{ '/blogs/notes/notes-page.css' | relative_url }}}}" />

{{% include kernel-notes-nav.html %}}

<section id="back">
<div id="blueback">

<div class="note-content" markdown="1">

# {title}
{tags_html}
{meta_html}
{content}

</div>

</div>
</section>

<script src="{{{{ '/blogs/notes/notes-nav.js' | relative_url }}}}"></script>
"""


def write_nav_include(categories, includes_dir, dry_run):
    lines = [
        '<div class="notes-floating-nav" id="notes-nav">',
        '  <button type="button" class="notes-nav-toggle" aria-expanded="false" aria-controls="notes-nav-panel">',
        '    <span>Sections</span>',
        '  </button>',
        '  <div class="notes-nav-panel" id="notes-nav-panel">',
        '    <div class="notes-nav-title">Kernel Exploitation Notes</div>',
        '    <ul class="notes-nav-overview">',
        '      <li><a href="{{ \'' + BASE_URL + '\' | relative_url }}"{% if page.note_id == \'overview\' %} class="is-active"{% endif %}>Overview</a></li>',
        '    </ul>',
    ]
    def nav_note_li(indent, cat_slug, note_slug, title):
        href = "{}{}/{}/".format(BASE_URL, cat_slug, note_slug)
        note_id = "{}/{}".format(cat_slug, note_slug)
        return '{}<li><a href="{{{{ \'{}\' | relative_url }}}}"{{% if page.note_id == \'{}\' %}} class="is-active"{{% endif %}}>{}</a></li>'.format(
            indent, href, note_id, title
        )

    for cat_slug, cat_title, cat_dir, items in categories:
        lines.append('    <div class="notes-nav-group-title">{}</div>'.format(cat_title))
        lines.append('    <ul>')
        for item in items:
            if item[0] == "note":
                _, src_name, note_slug, title = item
                lines.append(nav_note_li('      ', cat_slug, note_slug, title))
            else:
                _, sub_slug, sub_title, sub_dir, group_notes = item
                lines.append('      <li>')
                lines.append('        <div class="notes-nav-subgroup-title">{}</div>'.format(sub_title))
                lines.append('        <ul class="notes-nav-sublist">')
                for src_name, note_slug, title in group_notes:
                    lines.append(nav_note_li('          ', cat_slug, sub_slug + "/" + note_slug, title))
                lines.append('        </ul>')
                lines.append('      </li>')
        lines.append('    </ul>')
    lines.append('  </div>')
    lines.append('</div>')

    out_path = os.path.join(includes_dir, "kernel-notes-nav.html")
    content = "\n".join(lines) + "\n"
    if dry_run:
        print("[dry-run] would write", out_path)
        return
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("wrote", out_path)


def render_search_block():
    """Just the markup — no data. The index itself lives in a separate
    generated file (see write_search_data) loaded via <script src>, so
    index.md's source doesn't carry a giant inlined JSON blob."""
    lines = [
        '<div class="notes-search" id="notes-search">',
        '  <input type="text" id="notes-search-input" class="notes-search-input"',
        '         placeholder="Search notes... ( / to focus )" autocomplete="off" spellcheck="false"',
        '         aria-label="Search kernel exploitation notes" aria-controls="notes-search-results" />',
        '  <div class="notes-search-results" id="notes-search-results" role="listbox" hidden></div>',
        '</div>',
    ]
    return "\n".join(lines)


def write_search_data(entries, out_root, dry_run):
    """entries: [{title, breadcrumb, href, text}, ...] — one per note, built
    in main() while each note is already open for processing (so full body
    text is available, not just title/slug). 'text' backs in-body matches
    like 'kmalloc-' finding every note that mentions any kmalloc-N size.

    Written as its own small JS file (not embedded in index.md) so the page
    source stays readable and the data can be cached/loaded independently."""
    out_path = os.path.join(out_root, "search-data.js")
    content = "// Auto-generated by scripts/sync_kernel_notes.py — do not hand-edit.\n"
    content += "window.NOTES_SEARCH_INDEX = " + json.dumps(entries, ensure_ascii=False, indent=None) + ";\n"
    if dry_run:
        print("[dry-run] would write", out_path)
        return
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("wrote", out_path)


def render_tree(categories):
    lines = ['<pre class="notes-tree">']
    n_cats = len(categories)

    def tree_note_line(branch, cat_slug, note_slug, title):
        href = "{}{}/{}/".format(BASE_URL, cat_slug, note_slug)
        return '{}<a href="{{{{ \'{}\' | relative_url }}}}">{}</a>'.format(branch, href, title)

    for ci, (cat_slug, cat_title, cat_dir, items) in enumerate(categories):
        cat_last = ci == n_cats - 1
        cat_branch = "└── " if cat_last else "├── "
        child_indent = "    " if cat_last else "│   "
        lines.append('{}<span class="notes-tree-cat">{}/</span>'.format(cat_branch, cat_title))
        n_items = len(items)
        for ii, item in enumerate(items):
            item_last = ii == n_items - 1
            item_branch = child_indent + ("└── " if item_last else "├── ")
            if item[0] == "note":
                _, src_name, note_slug, title = item
                lines.append(tree_note_line(item_branch, cat_slug, note_slug, title))
            else:
                _, sub_slug, sub_title, sub_dir, group_notes = item
                lines.append('{}<span class="notes-tree-subcat">{}/</span>'.format(item_branch, sub_title))
                sub_indent = child_indent + ("    " if item_last else "│   ")
                n_group = len(group_notes)
                for gi, (src_name, note_slug, title) in enumerate(group_notes):
                    group_branch = sub_indent + ("└── " if gi == n_group - 1 else "├── ")
                    lines.append(tree_note_line(group_branch, cat_slug, sub_slug + "/" + note_slug, title))
    lines.append('</pre>')
    return "\n".join(lines)


DEFAULT_INTRO = """These are my running notes on Linux kernel internals and exploitation, built up while
working through kernel pwn challenges and reading the source tree directly. Every claim here is
something I traced through actual kernel code rather than repeated from a blog post, and the
call chains, struct layouts, and offsets are ones I verified myself, not assumed. The notes are
grouped roughly the way I think about kernel exploitation: understand the allocators first
(Internals), learn how to groom the heap into a useful layout (Heap Spraying, Page Spraying),
build a working ROP chain once you have control (KROP), and know what to actually overwrite once
you have arbitrary read/write (Targets). Some notes below are still stubs — I'd rather publish an
outline than wait for something polished before sharing it. Updated whenever I dig further into
something new."""


def load_intro(out_root, dry_run):
    intro_path = os.path.join(out_root, "_intro.md")
    if os.path.exists(intro_path):
        with open(intro_path, encoding="utf-8") as f:
            return f.read().strip()
    text = " ".join(DEFAULT_INTRO.split())
    if dry_run:
        print("[dry-run] would create", intro_path, "with a default intro paragraph")
    else:
        os.makedirs(out_root, exist_ok=True)
        with open(intro_path, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote", intro_path, "(edit this file directly — reruns never overwrite it)")
    return text


def write_index(categories, out_root, dry_run):
    intro_text = load_intro(out_root, dry_run)
    lines = [
        "---", "layout: default", 'title: "Kernel Exploitation Notes"',
        'description: "Linux kernel internals and exploitation notes — allocators, heap spraying, ROP, page spraying, and common targets."',
        'og_description: "Linux kernel internals and exploitation notes — allocators, heap spraying, ROP, page spraying, and common targets."',
        'og_type: "article"',
        'keywords: "kernel exploitation, linux kernel internals, heap spraying, rop, page spraying, zoozoo-sec"',
        "permalink: " + BASE_URL, "note_id: overview", "---", "",
        '<link rel="stylesheet" href="{{ \'/blogs/notes/notes-page.css\' | relative_url }}" />',
        "{% include kernel-notes-nav.html %}", "",
        '<section id="back">', '<div id="blueback">', "",
        '<div class="note-content" markdown="1">', "",
        "# Linux Kernel Exploitation Notes", "",
        intro_text,
        "", "</div>",
        "",
    ]

    lines.append(render_search_block())
    lines.append('')
    lines.append(render_tree(categories))
    lines.append('')
    lines.append('</div>')
    lines.append('</section>')
    lines.append('')
    lines.append("<script src=\"{{ '/blogs/notes/notes-nav.js' | relative_url }}\"></script>")
    lines.append("<script src=\"{{ '/blogs/notes/kernel-exploitation/search-data.js' | relative_url }}\"></script>")
    lines.append("<script src=\"{{ '/blogs/notes/notes-search.js' | relative_url }}\"></script>")

    out_path = os.path.join(out_root, "index.md")
    content = "\n".join(lines) + "\n"
    if dry_run:
        print("[dry-run] would write", out_path)
        return
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("wrote", out_path)


def scan_existing_pages(out_root):
    """Walk every already-published .md page under out_root/<category>/,
    including one level of subgroup nesting, skipping assets/ folders."""
    if not os.path.isdir(out_root):
        return
    for cat_name in sorted(os.listdir(out_root)):
        cat_path = os.path.join(out_root, cat_name)
        if not os.path.isdir(cat_path) or cat_name.startswith("."):
            continue
        for fname in sorted(os.listdir(cat_path)):
            fpath = os.path.join(cat_path, fname)
            if fname == "assets" or fname.startswith("."):
                continue
            if os.path.isdir(fpath):
                for sub_fname in sorted(os.listdir(fpath)):
                    if sub_fname.endswith(".md"):
                        yield os.path.join(fpath, sub_fname)
            elif fname.endswith(".md"):
                yield fpath


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vault", default=DEFAULT_VAULT, help="Path to the Obsidian vault's Internals-level folder")
    ap.add_argument("--site-root", default=DEFAULT_SITE_ROOT, help="Path to the Jekyll site root")
    ap.add_argument("--dry-run", action="store_true", help="Print what would happen without writing anything")
    ap.add_argument("--prune", action="store_true", help="Delete site pages whose source note no longer exists")
    ap.add_argument("--skip-index", action="store_true",
                     help="Don't touch index.md — use this once you've hand-edited it beyond what "
                          "_intro.md + the auto tree can express (e.g. added images), so a resync "
                          "doesn't overwrite your changes.")
    args = ap.parse_args()

    vault_root = os.path.expanduser(args.vault)
    if not os.path.isdir(vault_root):
        sys.exit("Vault not found: " + vault_root)

    out_root = os.path.join(args.site_root, "blogs", "notes", "kernel-exploitation")
    includes_dir = os.path.join(args.site_root, "_includes")

    categories = discover_vault(vault_root)
    if not categories:
        sys.exit("No categories/notes found under " + vault_root)

    lookup = build_lookup(categories)

    written_paths = set()
    search_entries = []
    for cat_slug, cat_title, cat_dir, items in categories:
        out_cat_dir = os.path.join(out_root, cat_slug)
        out_assets_dir = os.path.join(out_cat_dir, "assets")
        if not args.dry_run:
            os.makedirs(out_cat_dir, exist_ok=True)

        for rel_parts, src_name, note_slug, title, note_path, breadcrumb in flatten_items(cat_title, items):
            src_path = os.path.join(vault_root, cat_dir, *rel_parts, src_name)
            r = process_note(src_path, cat_slug, note_path, title, vault_root, lookup, out_assets_dir)

            search_entries.append({
                "title": title, "breadcrumb": breadcrumb,
                "href": BASE_URL + cat_slug + "/" + note_path + "/",
                "text": r["search_text"],
            })

            if r["tags"]:
                pills = "".join('<span class="note-tag">#{}</span>'.format(t) for t in r["tags"])
                tags_html = '\n<div class="note-tags">{}</div>\n'.format(pills)
            else:
                tags_html = ""

            page = PAGE_TEMPLATE.format(
                title=title,
                description="Kernel exploitation notes ({}): {}".format(cat_title, title),
                slug_keywords=(cat_slug + " " + note_path).replace("-", " ").replace("/", " "),
                permalink=BASE_URL + cat_slug + "/" + note_path + "/",
                cat_slug=cat_slug, note_slug=note_path,
                tags_html=tags_html, meta_html=r["meta_html"], content=r["body"],
            )
            out_note_dir = os.path.join(out_cat_dir, *note_path.split("/")[:-1])
            if not args.dry_run:
                os.makedirs(out_note_dir, exist_ok=True)
            out_path = os.path.join(out_note_dir, note_slug + ".md")
            written_paths.add(out_path)
            if args.dry_run:
                print("[dry-run] would write", out_path)
                continue
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(page)
            print("wrote", out_path)

    write_nav_include(categories, includes_dir, args.dry_run)
    write_search_data(search_entries, out_root, args.dry_run)
    if args.skip_index:
        print("skipped index.md (--skip-index)")
    else:
        write_index(categories, out_root, args.dry_run)

    if args.prune:
        for fpath in scan_existing_pages(out_root):
            if fpath not in written_paths:
                if args.dry_run:
                    print("[dry-run] would prune", fpath)
                else:
                    os.remove(fpath)
                    print("pruned", fpath)
    else:
        for fpath in scan_existing_pages(out_root):
            if fpath not in written_paths:
                print("NOTE: {} has no matching source note (run with --prune to remove it)".format(
                    os.path.relpath(fpath, out_root)))

    total_notes = len(search_entries)
    print("\nDone. {} categories, {} notes.".format(len(categories), total_notes))


if __name__ == "__main__":
    main()
