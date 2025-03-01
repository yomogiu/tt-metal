#!/usr/bin/env python3
import re
import json

def parse_dependencies_sh(file_path):
    """Extract dependency names from install_dependencies.sh (e.g. apt-get install lines)."""
    dependencies = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                # Look for lines that install packages (adjust the regex as needed)
                match = re.search(r'apt-get\s+install\s+([^\n]+)', line)
                if match:
                    # Split package names by whitespace and add them
                    pkgs = match.group(1).strip().split()
                    dependencies.extend(pkgs)
    except FileNotFoundError:
        print(f"{file_path} not found.")
    return dependencies

def parse_cmakelists(file_path):
    """Extract dependency names from find_package calls in CMakeLists.txt."""
    components = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                # Match lines like: find_package(PackageName ... )
                match = re.search(r'find_package\(\s*([^\s\)]+)', line)
                if match:
                    pkg = match.group(1).strip()
                    components.append(pkg)
    except FileNotFoundError:
        print(f"{file_path} not found.")
    return components

def main():
    deps_from_sh = parse_dependencies_sh("install_dependencies.sh")
    deps_from_cmake = parse_cmakelists("CMakeLists.txt")
    
    # Remove duplicates
    deps_from_sh = list(set(deps_from_sh))
    deps_from_cmake = list(set(deps_from_cmake))
    
    components = []
    for dep in deps_from_sh:
        components.append({
            "name": dep,
            "version": "N/A",
            "type": "library",
            "source": "install_dependencies.sh"
        })
    for comp in deps_from_cmake:
        components.append({
            "name": comp,
            "version": "N/A",
            "type": "library",
            "source": "CMakeLists.txt"
        })
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": components
    }
    
    with open("sbom.json", "w") as out:
        json.dump(sbom, out, indent=2)
    
    print("SBOM generated as sbom.json")

if __name__ == "__main__":
    main()
