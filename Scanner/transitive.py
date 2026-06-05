import json
import sys
import subprocess
import shutil
from pathlib import Path

from Scanner.parsers import parse_requirements_txt


def resolve_python_transitive(project_path):
    requirements_file = Path(project_path) / "requirements.txt"
    if not requirements_file.exists():
        return []

    print("  resolving transitive dependencies for Python...")

    try:
        result = subprocess.run(
            [
                sys.executable, "-m", "pip", "install",
                "--dry-run",
                "--quiet",
                "--ignore-installed",
                "--report", "-",
                "-r", str(requirements_file)
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            print(f"  warning: could not resolve full Python tree ({result.stderr.strip()[:100]})")
            return []

        report = json.loads(result.stdout)
        transitive_deps = []

        direct = parse_requirements_txt(requirements_file)
        direct_names = {d["name"].lower() for d in direct}

        for item in report.get("install", []):
            meta = item.get("metadata", {})
            name = meta.get("name", "")
            version = meta.get("version", "")
            if not name or not version:
                continue

            is_transitive = name.lower() not in direct_names
            transitive_deps.append({
                "name": name,
                "version": version,
                "ecosystem": "PyPI",
                "raw": f"{name}=={version}",
                "transitive": is_transitive
            })

        transitive_count = sum(1 for d in transitive_deps if d["transitive"])
        print(f"  resolved {len(transitive_deps)} total packages ({transitive_count} transitive)")
        return transitive_deps

    except subprocess.TimeoutExpired:
        print("  warning: Python transitive resolution timed out, falling back to direct deps only")
        return []
    except Exception as e:
        print(f"  warning: could not resolve Python transitive deps ({e})")
        return []


def resolve_node_transitive(project_path):
    package_json = Path(project_path) / "package.json"
    if not package_json.exists():
        return []

    if not shutil.which("npm"):
        print("  warning: npm not found, skipping Node transitive resolution")
        return []

    print("  resolving transitive dependencies for Node.js...")

    try:
        subprocess.run(
            ["npm", "install", "--package-lock-only", "--silent"],
            cwd=str(project_path),
            capture_output=True,
            timeout=120
        )

        result = subprocess.run(
            ["npm", "list", "--all", "--json", "--silent"],
            cwd=str(project_path),
            capture_output=True,
            text=True,
            timeout=60
        )

        try:
            tree = json.loads(result.stdout)
        except json.JSONDecodeError:
            print("  warning: could not parse npm list output")
            return []

        with open(package_json) as f:
            pkg = json.load(f)
        direct_names = set()
        direct_names.update(pkg.get("dependencies", {}).keys())
        direct_names.update(pkg.get("devDependencies", {}).keys())

        seen = set()
        transitive_deps = []

        def walk(node, depth=0):
            for name, info in node.get("dependencies", {}).items():
                version = info.get("version", "")
                key = f"{name}@{version}"
                if key in seen or not version:
                    continue
                seen.add(key)
                transitive_deps.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "raw": key,
                    "transitive": name not in direct_names
                })
                walk(info, depth + 1)

        walk(tree)

        transitive_count = sum(1 for d in transitive_deps if d["transitive"])
        print(f"  resolved {len(transitive_deps)} total packages ({transitive_count} transitive)")
        return transitive_deps

    except subprocess.TimeoutExpired:
        print("  warning: Node transitive resolution timed out, falling back to direct deps only")
        return []
    except Exception as e:
        print(f"  warning: could not resolve Node transitive deps ({e})")
        return []