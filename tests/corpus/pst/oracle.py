#!/usr/bin/env python3
"""Valeurs de référence du corpus PST/OST, produites par libpff (pypff), lecteur indépendant.

libpff n'est qu'un outil de développement : il n'est jamais embarqué dans le produit.
Usage : python3 -I tests/corpus/pst/oracle.py > tests/corpus/pst/expected.json
"""
import hashlib, json, os, sys
import pypff

HERE = os.path.dirname(os.path.abspath(__file__))
ENC = {0: "none", 1: "permute", 2: "cyclic"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk(folder, path, out, stats):
    items = atts = 0
    for i in range(folder.number_of_sub_messages):
        try:
            m = folder.get_sub_message(i)
            items += 1
            atts += m.number_of_attachments
        except Exception:
            stats["unreadable"] += 1
    if items:
        out.append({"name": path[-1] if path else "", "items": items, "attachments": atts})
    stats["items"] += items
    stats["attachments"] += atts
    for i in range(folder.number_of_sub_folders):
        sub = folder.get_sub_folder(i)
        walk(sub, path + [sub.name or ""], out, stats)


def describe(rel):
    path = os.path.join(HERE, rel)
    f = pypff.file()
    f.open(path)
    folders, stats = [], {"items": 0, "attachments": 0, "unreadable": 0}
    walk(f.get_root_folder(), [], folders, stats)
    folders.sort(key=lambda x: (x["name"], x["items"], x["attachments"]))
    return {
        "file": rel,
        "size": os.path.getsize(path),
        "sha256": sha256(path),
        "encoding": ENC.get(f.encryption_type, str(f.encryption_type)),
        "total_items": stats["items"],
        "total_attachments": stats["attachments"],
        "libpff_unreadable": stats["unreadable"],
        "folders_with_items": folders,
    }


files = sorted(p for p in os.listdir(HERE) if p.endswith((".pst", ".ost")))
files += sorted("large/" + p for p in os.listdir(os.path.join(HERE, "large")) if p.endswith((".pst", ".ost"))) if os.path.isdir(os.path.join(HERE, "large")) else []
json.dump({"generator": f"libpff {pypff.get_version()}", "files": [describe(p) for p in files]}, sys.stdout, ensure_ascii=False, indent=1)
print()
