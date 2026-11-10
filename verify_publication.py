"""Check offline HTML links, shared navigation, evidence consistency, and the public file boundary.

SPDX-License-Identifier: GPL-2.0-only
"""
from html.parser import HTMLParser
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.links, self.tags = [], [], []
        self.lang = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if tag == "html":
            self.lang = a.get("lang")
        if "id" in a:
            self.ids.append(a["id"])
        for key in ("href", "src", "srcset"):
            if key in a:
                self.links.append(a[key])
        if tag == "img":
            assert a.get("alt"), "image needs alternative text"


def main():
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root / "tools"))
    from site_chrome import Site
    site = Site()
    files = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=root, text=True).splitlines()
    documents = {root / name: Document((root / name).read_text(encoding="utf-8"))
                 for name in files if name.endswith(".html")}
    text = (root / "analysis/firmware-structure.html").read_text(encoding="utf-8")
    local = 0
    for source, doc in documents.items():
        assert doc.lang == "ko" and doc.tags.count("h1") == 1 and doc.tags.count("main") == 1, source
        assert len(doc.ids) == len(set(doc.ids)), f"duplicate HTML IDs: {source}"
        body = source.read_text(encoding="utf-8")
        assert "{{" not in body and "<!-- HUMANIZE" not in body and "STUB-PLACEHOLDER" not in body, source
        name = source.relative_to(root).as_posix()
        assert name in site.index, f"{name} is not listed in site-map.json"
        assert "assets/site.css" in body, f"{name} must link the shared stylesheet"
        assert site.render(name, body) == body, f"{name}: navigation is stale; run python tools/site_chrome.py"
        for link in doc.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                assert url.scheme == "https", link
                continue
            path = (source.parent / unquote(url.path)).resolve() if url.path else source
            assert path.is_relative_to(root) and path.is_file(), link
            assert ".private" not in path.relative_to(root).parts, link
            if url.fragment and path in documents:
                assert unquote(url.fragment) in documents[path].ids, link
            local += 1
    for path in (root / "assets").glob("*.svg"):
        ET.parse(path)
    inventory = json.loads((root / "analysis/inventory.json").read_text(encoding="utf-8"))
    findings = json.loads((root / "analysis/findings.json").read_text(encoding="utf-8"))
    package = json.loads((root / "analysis/official-package.json").read_text(encoding="utf-8"))
    comparison = json.loads((root / "analysis/decoder-comparison.json").read_text(encoding="utf-8"))
    assert inventory["input"]["sha256"] == package["firmware_sha256"] and package["matches_user_file"]
    assert inventory["decoded"]["sha256"] == findings["decoded_sha256"] == comparison["sha256"]
    assert comparison["matched"] and comparison["bytes"] == findings["decoded_size"]
    assert findings["midr_check"]["part_number"] == 0xC09
    for value in (inventory["input"]["sha256"], findings["decoded_sha256"], "0x02000000", "0xC090", "30,254"):
        assert value in text, value
    for name in ("hardware", "raw-path", "raw-numeric", "tone-path", "tone-numeric", "selector-path", "isp-paths", "isp-numeric", "pipeline-flow", "jpeg-buffers", "menu-events", "exif-output", "filesystem-backend", "sd-controller", "alternate-buffers", "backend-b", "cpp-handoff", "masked-scaler", "mode-reachability", "superresolution-menu", "buffer-history", "scaler-gate", "repack", "af-drive", "installation", "ui-resources", "af-control", "af-input", "ui-dispatch", "preserved-record", "pixel-records", "pixel-policy", "capture-prepare", "store-image-records", "preserved-sector20", "preserved-config", "preserved-dispatch", "color-ui", "settings-storage"):
        evidence = json.loads((root / f"analysis/{name}.json").read_text(encoding="utf-8"))
        assert evidence["decoded_sha256"] == findings["decoded_sha256"], name
    rebuilt = json.loads((root / "analysis/tone-rebuild.json").read_text(encoding="utf-8"))
    assert rebuilt["source_image_sha256"] == findings["decoded_sha256"]
    source = (root / rebuilt["c_source"]).read_text(encoding="utf-8").encode("utf-8")
    assert sha256(source).hexdigest() == rebuilt["c_source_sha256"]
    for name in files:
        path = Path(name)
        assert not any(part in {".private", "_workspace", "__pycache__"} for part in path.parts), name
        assert path.suffix.lower() not in {".bin", ".zip", ".pyc", ".exe", ".dll"}, name
    print(json.dumps({"passed": True, "html_documents_checked": len(documents), "local_links_checked": local, "public_files_checked": len(files),
                      "evidence_identity_consistent": True, "svg_xml_valid": True}, indent=2))


if __name__ == "__main__":
    main()
