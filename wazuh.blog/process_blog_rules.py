#!/usr/bin/env python3
"""
tick@linuxmafia.pl
Process Wazuh blog extracted rules/decoders/integrations.
- Group by OS/system
- Remap rule IDs per OS range (no conflicts)
- Output production-ready XML files
"""

import json
import re
import os
from collections import defaultdict
from pathlib import Path

EXTRACT_FILE = Path(__file__).parent.parent / "hunts/2026-06-13/wazuh-blog-rules-extract.json"
OUT_DIR = Path(__file__).parent

# Non-overlapping ID ranges per OS (start, end)
# Wazuh custom rules: 100000-999999 (user space)
# We assign 10k blocks per OS to avoid any overlap
OS_RANGES = {
    "linux":          (200000, 209999),
    "windows":        (210000, 219999),
    "macos":          (220000, 229999),
    "kubernetes":     (230000, 239999),
    "cloud":          (240000, 249999),
    "mongodb":        (250000, 259999),
    "dns":            (260000, 269999),
    "cross-platform": (270000, 299999),
}

# Map article-level OS tags to canonical keys
OS_ALIASES = {
    "linux": "linux",
    "windows": "windows",
    "macos": "macos",
    "kubernetes": "kubernetes",
    "cloud": "cloud",
    "mongodb": "mongodb",
    "dns": "dns",
    "cross-platform": "cross-platform",
}


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]


def extract_rule_ids(xml: str) -> list[str]:
    return re.findall(r'<rule\s+id=["\'](\d+)["\']', xml)


def remap_rule_ids(xml: str, id_map: dict[str, str]) -> str:
    """Replace rule IDs and any <if_sid>/<same_id> references."""
    def replace_rule_id(m):
        old = m.group(1)
        return m.group(0).replace(old, id_map.get(old, old))

    # Replace rule id= attribute
    xml = re.sub(r'(<rule\s+id=["\'])(\d+)(["\'])', lambda m: m.group(1) + id_map.get(m.group(2), m.group(2)) + m.group(3), xml)
    # Replace if_sid references
    def replace_sid(m):
        sids = m.group(1)
        new_sids = ",".join(id_map.get(s.strip(), s.strip()) for s in sids.split(","))
        return m.group(0).replace(sids, new_sids)
    xml = re.sub(r'<if_sid>([^<]+)</if_sid>', replace_sid, xml)
    xml = re.sub(r'<same_id>([^<]+)</same_id>', replace_sid, xml)
    return xml


def wrap_xml_rules(rules_xml_list: list[str], group_name: str) -> str:
    """Wrap multiple rule blocks into a single valid Wazuh rules file."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', f'<!-- Group: {group_name} -->', '<group name="wazuh_blog_custom,">']
    for block in rules_xml_list:
        # Strip any existing outer <group> wrappers to flatten
        block = re.sub(r'</?group[^>]*>', '', block).strip()
        if block:
            lines.append(block)
    lines.append('</group>')
    return "\n".join(lines)


def wrap_xml_decoders(decoders_xml_list: list[str]) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    for block in decoders_xml_list:
        lines.append(block.strip())
    return "\n".join(lines)


def main():
    with open(EXTRACT_FILE) as f:
        data = json.load(f)

    # Collect rules/decoders/integrations per OS
    by_os: dict[str, dict] = {os: {"rules": [], "decoders": [], "integrations": [], "scripts": []} for os in OS_RANGES}

    articles_by_os: dict[str, list] = defaultdict(list)
    for item in data:
        os_key = OS_ALIASES.get(item.get("os_target", "cross-platform"), "cross-platform")
        articles_by_os[os_key].append(item)

    # Running counters per OS — each rule FILE gets its own sequential block of new IDs
    os_counters: dict[str, int] = {os: OS_RANGES[os][0] for os in OS_RANGES}
    # Full remap log for audit: (os, old_id) -> new_id
    full_remap_log: dict[str, dict[str, str]] = {os: {} for os in OS_RANGES}

    for os_key, articles in articles_by_os.items():
        counter = os_counters[os_key]
        end = OS_RANGES[os_key][1]

        for item in articles:
            slug = slugify(item["article"])
            for f in item.get("files", []):
                ftype = f.get("type", "unknown")
                content = f.get("content", "").strip()
                if not content:
                    continue

                meta_comment = f"<!-- Source: {item['url']} | Article: {item['article']} -->\n"

                if ftype == "rule":
                    # Per-file remap: each unique old ID in THIS file gets a fresh new ID
                    old_ids = list(dict.fromkeys(extract_rule_ids(content)))  # preserve order, dedupe
                    file_id_map: dict[str, str] = {}
                    for old_id in old_ids:
                        if counter > end:
                            print(f"WARNING: OS '{os_key}' exceeded ID range at article: {item['article']}")
                            break
                        file_id_map[old_id] = str(counter)
                        full_remap_log[os_key][f"{slug}:{old_id}"] = str(counter)
                        counter += 1

                    remapped = remap_rule_ids(content, file_id_map)
                    by_os[os_key]["rules"].append((slug, meta_comment + remapped))

                elif ftype == "decoder":
                    by_os[os_key]["decoders"].append((slug, meta_comment + content))
                elif ftype == "integration":
                    by_os[os_key]["integrations"].append((slug, meta_comment + content))
                elif ftype == "script":
                    by_os[os_key]["scripts"].append((slug, meta_comment + content))

        os_counters[os_key] = counter

    global_id_remap = full_remap_log

    # Write output files
    stats = {}
    for os_key, collections in by_os.items():
        os_stats = {}

        # Rules — merge all into one file per OS
        if collections["rules"]:
            rules_xml_list = [block for _, block in collections["rules"]]
            merged = wrap_xml_rules(rules_xml_list, os_key)
            out_path = OUT_DIR / "rules" / os_key / f"local_rules_{os_key}.xml"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(merged)
            os_stats["rules"] = len(collections["rules"])

        # Decoders — merge per OS
        if collections["decoders"]:
            dec_list = [block for _, block in collections["decoders"]]
            merged = wrap_xml_decoders(dec_list)
            out_path = OUT_DIR / "decoders" / os_key / f"local_decoders_{os_key}.xml"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(merged)
            os_stats["decoders"] = len(collections["decoders"])

        # Integrations — one file per article slug
        if collections["integrations"]:
            int_dir = OUT_DIR / "integrations" / os_key
            int_dir.mkdir(parents=True, exist_ok=True)
            seen_slugs: dict[str, int] = {}
            for slug, content in collections["integrations"]:
                count = seen_slugs.get(slug, 0)
                seen_slugs[slug] = count + 1
                fname = f"{slug}_{count}.conf" if count > 0 else f"{slug}.conf"
                (int_dir / fname).write_text(content)
            os_stats["integrations"] = len(collections["integrations"])

        # Scripts — one file per article slug
        if collections["scripts"]:
            scr_dir = OUT_DIR / "scripts" / os_key
            scr_dir.mkdir(parents=True, exist_ok=True)
            seen_slugs = {}
            for slug, content in collections["scripts"]:
                count = seen_slugs.get(slug, 0)
                seen_slugs[slug] = count + 1
                ext = ".py" if "import " in content or "def " in content or "#!/usr/bin/env python" in content else ".sh"
                fname = f"{slug}_{count}{ext}" if count > 0 else f"{slug}{ext}"
                (scr_dir / fname).write_text(content)
            os_stats["scripts"] = len(collections["scripts"])

        stats[os_key] = os_stats

    # Write ID remap index
    remap_out = OUT_DIR / "rule_id_remap.json"
    remap_out.write_text(json.dumps(global_id_remap, indent=2))

    # Summary
    print("=== Wazuh Blog Rules Processing Complete ===")
    print(f"\nOutput: {OUT_DIR}")
    print("\nFiles per OS:")
    for os_key, s in stats.items():
        if s:
            parts = [f"{v} {k}" for k, v in s.items()]
            print(f"  {os_key:20s}: {', '.join(parts)}")
    print(f"\nID remap table: {remap_out}")
    print("\nID ranges assigned:")
    for os_key, (start, end) in OS_RANGES.items():
        count = len(global_id_remap.get(os_key, {}))
        print(f"  {os_key:20s}: {start}-{end} ({count} IDs remapped)")


if __name__ == "__main__":
    main()
