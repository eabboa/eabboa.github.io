#!/usr/bin/env python3

"""

Auto-generates the portfolio section of README.md from folder contents.

Run from repo root. Rewrites content between markers.



Markers in README.md:

    <!-- PORTFOLIO:START -->

    <!-- PORTFOLIO:END -->

"""



import os

import re

from pathlib import Path


# ── Config ────────────────────────────────────────────────────────────────────

# Top-level folders to include (order preserved)
TRACKED_DIRS = [
    "Malware-Analysis",
    "Network-Forensics",
    "SIEM-Hunting",
    "Incident-Response",
    "Detection-Engineering",
]

# Folder-level descriptions (shown as the parent bullet subtitle)
DIR_META = {
    "Malware-Analysis": "Static & Dynamic triage of obfuscated payloads (e.g., Cryptbot, Loaders). IOC extraction and MITRE ATT&CK mapping.",
    "Network-Forensics": "PCAP analysis, C2 traffic identification, and protocol abuse detection.",
    "SIEM-Hunting":      "Splunk/ELK queries, Sigma rules, and brute-force detection.",
    "Incident-Response": "Forensic timeline reconstruction, live triage, and containment playbooks for active breaches.",
    "Detection-Engineering": "Custom YARA/Snort signatures, proactive alert creation, and false-positive tuning against adversary tradecraft.",
}

# File extensions to list as sub-items (others ignored)

INCLUDE_EXT = {".md", ".ipynb", ".py", ".txt", ".json", ".yml", ".yaml", ".pcap", ".evtx"}



# Files to always skip

SKIP_FILES = {"README.md", ".gitkeep", ".DS_Store", "index.md"}



README_PATH = Path("index.md")

START_MARKER = "<!-- PORTFOLIO:START -->"

END_MARKER   = "<!-- PORTFOLIO:END -->"



# ── Helpers ───────────────────────────────────────────────────────────────────



def display_name(path: Path) -> str:

    """Convert filename to readable label while preserving technical casing."""

    # Replace separators and split into words

    words = path.stem.replace("-", " ").replace("_", " ").split()

    

    # Common connectors to keep lowercase

    lower_exceptions = {"and", "of", "to", "the", "for", "with", "in", "on", "at", "by", "a", "an"}

    

    formatted_words = []

    for i, word in enumerate(words):

        # Always capitalize the first word if it's all lowercase

        if i == 0:

            formatted_words.append(word if not word.islower() else word.capitalize())

        # Keep connectors lowercase

        elif word.lower() in lower_exceptions:

            formatted_words.append(word.lower())

        # Preserve words that already have uppercase letters (e.g., IcedID)

        elif not word.islower():

            formatted_words.append(word)

        # Capitalize standard lowercase words (e.g., analysis -> Analysis)

        else:

            formatted_words.append(word.capitalize())

            

    return " ".join(formatted_words)



def extract_description(filepath: Path) -> str:

    """Pull first non-empty, non-heading line from a .md file as description."""

    try:

        with open(filepath, encoding="utf-8", errors="ignore") as f:

            for line in f:

                line = line.strip()

                if line and not line.startswith("#") and not line.startswith("<!--"):

                    return line[:120] + ("…" if len(line) > 120 else "")

    except Exception:

        pass

    return ""



def collect_entries(folder: Path) -> list[dict]:

    """Walk a folder and return sorted file entries."""

    entries = []

    for item in sorted(folder.iterdir()):

        if item.is_dir():

            # Recurse one level

            sub_entries = collect_entries(item)

            if sub_entries:

                entries.append({"type": "subdir", "path": item, "children": sub_entries})

        elif item.is_file():

            if item.name in SKIP_FILES:

                continue

            if item.suffix.lower() not in INCLUDE_EXT:

                continue

            desc = extract_description(item) if item.suffix == ".md" else ""

            entries.append({"type": "file", "path": item, "desc": desc})

    return entries



def render_entries(entries: list[dict], depth: int = 2) -> list[str]:

    """Recursively render entries as markdown list items."""

    indent = "  " * depth

    lines = []

    for e in entries:

        rel = e["path"]

        link_path = str(rel).replace("\\", "/")

        name = display_name(e["path"])

        if e["type"] == "subdir":

            lines.append(f"{indent}* **[{name}](./{link_path}/)**")

            lines.extend(render_entries(e["children"], depth + 1))

        else:

            lines.append(f"{indent}* [{name}](./{link_path})")

    return lines



# ── Core ──────────────────────────────────────────────────────────────────────



def build_section() -> str:

    lines = [START_MARKER, ""]

    root = Path(".")



    for dir_name in TRACKED_DIRS:

        folder = root / dir_name

        if not folder.exists():

            print(f"  [SKIP] {dir_name} — not found")

            continue



        meta = DIR_META.get(dir_name, "")

        rel = dir_name.replace("\\", "/")

        lines.append(f"* **[{dir_name}](./{rel}/)**")

        if meta:

            lines.append(f"  * *{meta}*")



        entries = collect_entries(folder)

        if entries:

            lines.extend(render_entries(entries, depth=1))



        lines.append("")  # spacing



    lines.append(END_MARKER)

    return "\n".join(lines)





def update_readme(new_section: str):

    if not README_PATH.exists():

        README_PATH.write_text(new_section + "\n", encoding="utf-8")

        print("README.md created.")

        return



    content = README_PATH.read_text(encoding="utf-8")



    pattern = re.compile(

        rf"{re.escape(START_MARKER)}.*?{re.escape(END_MARKER)}",

        re.DOTALL

    )



    if pattern.search(content):

        updated = pattern.sub(new_section, content)

        README_PATH.write_text(updated, encoding="utf-8")

        print("README.md updated between markers.")

    else:

        # Append if markers missing

        README_PATH.write_text(content.rstrip() + "\n\n" + new_section + "\n", encoding="utf-8")

        print("Markers not found — section appended to README.md.")





if __name__ == "__main__":

    print("Scanning repo…")

    section = build_section()

    update_readme(section)

    print("Done.")