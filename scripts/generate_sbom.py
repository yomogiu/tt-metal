#!/usr/bin/env python3
import re
import json
import os

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
    return list(set(dependencies))

def parse_cmakelists(file_path):
    """Extract dependency names from find_package and add_subdirectory calls in CMakeLists.txt."""
    dependencies = []
    try:
        with open(file_path, "r") as f:
            content = f.read()
            
            # Extract dependencies from find_package() calls.
            # This regex finds the package name immediately following find_package(, ignoring case.
            find_package_matches = re.findall(r'find_package\s*\(\s*([^\s\)]+)', content, re.IGNORECASE)
            for dep in find_package_matches:
                dependencies.append({
                    "name": dep,
                    "version": "N/A",
                    "type": "library",
                    "source": "CMakeLists.txt (find_package)"
                })
            
            # Extract dependencies from add_subdirectory() calls that likely reference external dependencies.
            # For example, lines that include "dependencies" or "third_party" in the directory path.
            add_subdir_matches = re.findall(r'add_subdirectory\s*\(\s*([^\s\)]+)', content, re.IGNORECASE)
            for subdir in add_subdir_matches:
                # Only consider subdirectories that look like external dependencies.
                if "dependencies" in subdir or "third_party" in subdir:
                    # Normalize the dependency name (for example, use the base folder name)
                    dep_name = os.path.basename(subdir.strip())
                    dependencies.append({
                        "name": dep_name,
                        "version": "N/A",
                        "type": "library",
                        "source": "CMakeLists.txt (add_subdirectory)"
                    })
    except FileNotFoundError:
        print(f"{file_path} not found.")
    # Remove duplicates by dependency name and source.
    unique_deps = {}
    for dep in dependencies:
        key = (dep["name"], dep["source"])
        unique_deps[key] = dep
    return list(unique_deps.values())

def main():
    # Parse dependencies from the shell script and CMakeLists.txt
    deps_from_sh = parse_dependencies_sh("install_dependencies.sh")
    deps_from_cmake = parse_cmakelists("CMakeLists.txt")
    
    components = []
    for dep in deps_from_sh:
        components.append({
            "name": dep,
            "version": "N/A",
            "type": "library",
            "source": "install_dependencies.sh"
        })
    components.extend(deps_from_cmake)
    
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
