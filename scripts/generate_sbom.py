#!/usr/bin/env python3
import json
import re
from collections import defaultdict

def parse_install_script(content):
    components = defaultdict(dict)
    current_list = None
    
    # Extract package lists
    list_re = re.compile(r'^(UB_\w+_LIST)=\(([\s\S]*?)\)', re.MULTILINE)
    for match in list_re.finditer(content):
        list_name = match.group(1)
        packages = [p.strip('\\\n\t ') for p in match.group(2).split() if p.strip()]
        components[list_name] = packages

    # Extract versions
    version_vars = {
        'LLVM_VERSION': None,
        'TT_TOOLS_VERSION': None,
        'UBUNTU_CODENAME': None
    }
    
    for line in content.split('\n'):
        for var in version_vars:
            if line.strip().startswith(f"{var}="):
                version_vars[var] = line.split('=')[1].strip("'\"")
    
    # Extract .deb package info
    deb_pkg = re.search(r'tenstorrent-tools_(\$\{TT_TOOLS_VERSION\}\.deb)', content)
    if deb_pkg:
        components['deb_packages'] = [{
            'name': 'tenstorrent-tools',
            'version': version_vars['TT_TOOLS_VERSION'],
            'file': deb_pkg.group(1)
        }]
    
    # Extract GCC version
    gcc_ver = re.search(r'install_gcc12\(\) {.*?Ubuntu (\d+\.\d+)', content, re.DOTALL)
    if gcc_ver:
        components['gcc'] = {
            'version': '12',
            'ubuntu_version': gcc_ver.group(1)
        }
    
    return components, version_vars

def parse_cmakelists(content):
    components = {
        'subdirectories': [],
        'find_packages': [],
        'link_libraries': [],
        'external_deps': []
    }
    
    # Find subdirectories
    subdir_re = re.compile(r'add_subdirectory\(([^\s\)]+)')
    components['subdirectories'] = subdir_re.findall(content)
    
    # Find package dependencies
    find_pkg_re = re.compile(r'find_package\(([^\s\)]+)')
    components['find_packages'] = find_pkg_re.findall(content)
    
    # Find linked libraries
    link_lib_re = re.compile(r'target_link_libraries\(\s*\w+\s+INTERFACE\s+([^\)]+)', re.DOTALL)
    for match in link_lib_re.finditer(content):
        libs = [lib.strip() for lib in match.group(1).split()]
        components['link_libraries'].extend(libs)
    
    # Find CPM usage
    if 'include(CPM)' in content:
        components['external_deps'].append('CPM-managed dependencies')
    
    return components

def parse_dependencies_cmakelists(content):
    components = []
    cpm_pattern = re.compile(
        r'CPMAddPackage\(\s*'
        r'NAME\s+(\w+).*?'
        r'(?:GITHUB_REPOSITORY\s+([/\w-]+)|URL\s+"([^"]+)".*?URL_HASH\s+SHA256=(\w+))?.*?'
        r'(?:GIT_TAG\s+([^\s)]+))?.*?'
        r'(?:VERSION\s+([\d.]+))?',
        re.DOTALL
    )
    
    boost_pattern = re.compile(
        r'CPMAddPackage\(\s*NAME Boost.*?VERSION ([\d.]+).*?'
        r'boost-([\d.]+)-cmake\.tar\.xz.*?SHA256=(\w+)',
        re.DOTALL
    )

    # Parse Boost separately due to different structure
    boost_match = boost_pattern.search(content)
    if boost_match:
        components.append({
            "name": "Boost",
            "version": boost_match.group(1),
            "source": "CPM",
            "url": f"https://github.com/boostorg/boost/releases/download/boost-{boost_match.group(2)}/",
            "hash": f"SHA256:{boost_match.group(3)}"
        })

    # Parse other CPM packages
    for match in cpm_pattern.finditer(content):
        name = match.group(1)
        github_repo = match.group(2)
        url = match.group(3)
        version = match.group(6) or match.group(5)  # Prefer VERSION, fallback to GIT_TAG
        source = "GitHub" if github_repo else "URL" if url else "Unknown"

        if name == "Boost":  # Already handled
            continue

        component = {
            "name": name,
            "version": version.lstrip('v') if version else "unknown",
            "source": f"CPM ({source})",
            "type": "library"
        }

        if github_repo:
            component["purl"] = f"pkg:github/{github_repo}@{version}"
        elif url:
            component["url"] = url
            if match.group(4):  # SHA256 hash
                component["hash"] = f"SHA256:{match.group(4)}"

        components.append(component)

    return components

def generate_sbom(install_data, cmake_data, versions):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": []
    }
    
    # Add packages from install script
    pkg_lists = ['UB_RUNTIME_LIST', 'UB_BUILDTIME_LIST', 'UB_BAREMETAL_LIST']
    for pkg_list in pkg_lists:
        for pkg in install_data.get(pkg_list, []):
            sbom['components'].append({
                "name": pkg,
                "version": f"ubuntu-{versions['UBUNTU_CODENAME']}",
                "type": "library",
                "purl": f"pkg:deb/ubuntu/{pkg}?distro=ubuntu-{versions['UBUNTU_CODENAME']}",
                "source": "install_dependencies.sh"
            })
    
    # Add special components
    if install_data.get('deb_packages'):
        for deb in install_data['deb_packages']:
            sbom['components'].append({
                "name": deb['name'],
                "version": deb['version'],
                "type": "application",
                "purl": f"pkg:deb/tenstorrent/{deb['name']}@{deb['version']}",
                "source": "install_dependencies.sh"
            })
    
    # Add CMake components
    for subdir in cmake_data['subdirectories']:
        if subdir not in ['dependencies', 'tt_metal/third_party/umd']:
            continue
        sbom['components'].append({
            "name": subdir.split('/')[-1],
            "version": "git-submodule",
            "type": "library",
            "source": f"CMakeLists.txt (add_subdirectory {subdir})"
        })
    
    for pkg in cmake_data['find_packages']:
        sbom['components'].append({
            "name": pkg,
            "version": "system-provided",
            "type": "library",
            "source": "CMakeLists.txt (find_package)"
        })
    
    # Add linked libraries
    for lib in set(cmake_data['link_libraries']):
        if lib in ['dl', 'pthread', 'atomic']:  # Skip system libraries
            continue
        sbom['components'].append({
            "name": lib,
            "version": "system-provided",
            "type": "library",
            "source": "CMakeLists.txt (target_link_libraries)"
        })
    
    # Add compiler toolchain
    if install_data.get('gcc'):
        sbom['components'].append({
            "name": "gcc",
            "version": install_data['gcc']['version'],
            "type": "tool",
            "purl": f"pkg:apt/ubuntu/gcc-{install_data['gcc']['version']}",
            "source": "install_dependencies.sh"
        })

    # Add CPM dependencies
    for dep in deps_data:
        entry = {
            "name": dep["name"],
            "version": dep.get("version", "unknown"),
            "type": "library",
            "source": dep["source"],
            "purl": dep.get("purl", "")
        }
        if "hash" in dep:
            entry["hashes"] = [{"alg": "SHA256", "content": dep["hash"].split(':')[1]}]
        sbom["components"].append(entry)
    
    return sbom

if __name__ == "__main__":
    with open('CMakeLists.txt') as f:
        cmake_content = f.read()
    
    with open('install_dependencies.sh') as f:
        install_content = f.read()

    with open('dependencies/CMakeLists.txt') as f:
        deps_content = f.read()

    deps_data = parse_dependencies_cmakelists(deps_content)
    
    install_data, versions = parse_install_script(install_content)
    cmake_data = parse_cmakelists(cmake_content)
    
    sbom = generate_sbom(install_data, cmake_data, deps_data, versions)
    
    with open('sbom.json', 'w') as f:
        json.dump(sbom, f, indent=2)

    print("Generated comprehensive SBOM at sbom.json")
