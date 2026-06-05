import json
import re
from pathlib import Path


def parse_requirements_txt(filepath):
    deps = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([=<>!~]+)\s*([\d\.]+)", line)
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": match.group(3),
                    "ecosystem": "PyPI",
                    "raw": line,
                    "transitive": False
                })
            else:
                name = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if name:
                    deps.append({
                        "name": name.group(1),
                        "version": None,
                        "ecosystem": "PyPI",
                        "raw": line,
                        "transitive": False
                    })
    return deps


def parse_package_json(filepath):
    deps = []
    with open(filepath) as f:
        data = json.load(f)

    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for name, version_str in all_deps.items():
        clean_version = re.sub(r"^[\^~>=<*]+", "", version_str).strip()
        deps.append({
            "name": name,
            "version": clean_version if clean_version else None,
            "ecosystem": "npm",
            "raw": f"{name}@{version_str}",
            "transitive": False
        })
    return deps


def parse_gemfile_lock(filepath):
    deps = []
    in_gems = False
    with open(filepath) as f:
        for line in f:
            line = line.rstrip()
            if line == "GEM":
                in_gems = True
                continue
            if in_gems and line == "":
                in_gems = False
                continue
            if in_gems:
                match = re.match(r"^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([\d\.]+)\)", line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "RubyGems",
                        "raw": line.strip(),
                        "transitive": False
                    })
    return deps


def detect_and_parse(project_path, transitive=False):
    from Scanner.transitive import resolve_python_transitive, resolve_node_transitive

    project_path = Path(project_path)
    found = []

    checks = [
        (project_path / "requirements.txt", parse_requirements_txt, "requirements.txt", "python"),
        (project_path / "package.json",     parse_package_json,     "package.json",     "node"),
        (project_path / "Gemfile.lock",     parse_gemfile_lock,     "Gemfile.lock",     "ruby"),
    ]

    for path, parser, label, ecosystem_type in checks:
        if not path.exists():
            continue

        print(f"  found {label}")

        if transitive:
            if ecosystem_type == "python":
                resolved = resolve_python_transitive(project_path)
                if resolved:
                    found.extend(resolved)
                    continue
            elif ecosystem_type == "node":
                resolved = resolve_node_transitive(project_path)
                if resolved:
                    found.extend(resolved)
                    continue

        deps = parser(path)
        print(f"  {len(deps)} direct dependencies parsed")
        found.extend(deps)

    return found