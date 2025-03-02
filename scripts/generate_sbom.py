#!/usr/bin/env python3
import json
import re
import os
import base64
from datetime import datetime, UTC
from collections import defaultdict
from urllib.parse import urlparse

LICENSE_MAP = {
    "boost": "BSL-1.0",
    "yaml-cpp": "MIT",
    "googletest": "BSD-3-Clause",
    "pybind11": "BSD-3-Clause",
    "fmt": "MIT",
    "nlohmann/json": "MIT",
    "taskflow": "MIT",
    "flatbuffers": "Apache-2.0",
    "magic_enum": "MIT",
    "range-v3": "BSL-1.0",
    "xtensor": "BSD-3-Clause",
    "tenstorrent-tools": "Apache-2.0"
}

def parse_spdx_headers(content):
    headers = {
        "copyrights": set(),
        "licenses": set()
    }
    
    # Copyright detection
    copyright_matches = re.findall(
        r'SPDX-FileCopyrightText:\s*(©.*)',
        content
    )
    headers["copyrights"].update(copyright_matches)
    
    # License detection
    license_match = re.search(
        r'SPDX-License-Identifier:\s*([\w\.-]+)',
        content
    )
    if license_match:
        headers["licenses"].add(license_match.group(1))
        
    return headers

def parse_install_script(content):
    components = defaultdict(dict)
    version_vars = defaultdict(str)
    spdx = parse_spdx_headers(content)
    
    # Extract package lists
    list_re = re.compile(r'^(UB_\w+_LIST)=\(([\s\S]*?)\)', re.MULTILINE)
    for match in list_re.finditer(content):
        list_name = match.group(1)
        components[list_name] = [p.strip('\\\n\t "') for p in match.group(2).split() if p.strip()]
    
    # Extract versions
    version_pattern = re.compile(r'^\s*(\w+)=[\'"]([^\'"]+)[\'"]', re.MULTILINE)
    for match in version_pattern.finditer(content):
        version_vars[match.group(1)] = match.group(2)
    
    # Extract .deb package
    deb_pkg = re.search(r'tenstorrent-tools_(\$\{TT_TOOLS_VERSION\}\.deb)', content)
    if deb_pkg:
        components['deb_packages'] = [{
            'name': 'tenstorrent-tools',
            'version': version_vars.get('TT_TOOLS_VERSION', 'unknown'),
            'source': 'install_dependencies.sh',
            'spdx': spdx
        }]
    
    return components, version_vars

def parse_cmakelists(content, file_path):
    spdx = parse_spdx_headers(content)
    components = {
        'subdirectories': [],
        'find_packages': [],
        'link_libraries': [],
        'external_deps': [],
        'spdx': spdx
    }
    
    # Find subdirectories with SYSTEM modifier
    subdir_re = re.compile(r'add_subdirectory\(\s*([^\s\)]+)\s*(SYSTEM)?', re.IGNORECASE)
    for match in subdir_re.finditer(content):
        components['subdirectories'].append({
            'path': match.group(1),
            'system': bool(match.group(2)),
            'file': file_path,
            'spdx': spdx  # Add SPDX context from parent CMakeLists
        })
    
    # Find package dependencies
    find_pkg_re = re.compile(r'find_package\(\s*([^\s\)]+)')
    components['find_packages'] = list(set(find_pkg_re.findall(content)))
    
    # Find linked libraries
    link_lib_re = re.compile(r'target_link_libraries\(\s*\w+\s+(INTERFACE|PUBLIC|PRIVATE)\s+([^\)]+)', re.DOTALL)
    for match in link_lib_re.finditer(content):
        libs = [lib.strip() for lib in match.group(2).split() if lib.strip()]
        components['link_libraries'].extend(libs)
    
    # Detect CPM usage
    if 'include(CPM)' in content:
        components['external_deps'].append('CPM')
    
    return components

def parse_dependencies_cmakelists(content):
    components = []
    spdx = parse_spdx_headers(content)
    
    # Boost specific parsing
    boost_pattern = re.compile(
        r'CPMAddPackage\(\s*NAME Boost.*?VERSION ([\d.]+).*?'
        r'boost-([\d.]+)-cmake\.tar\.xz.*?SHA256=([0-9a-f]{64})',
        re.DOTALL
    )
    boost_match = boost_pattern.search(content)
    if boost_match:
        components.append({
            "name": "Boost",
            "version": boost_match.group(1),
            "source": "CPM",
            "purl": f"pkg:boost/boost@{boost_match.group(1)}",
            "url": f"https://github.com/boostorg/boost/releases/download/boost-{boost_match.group(2)}/",
            "hashes": [{"alg": "SHA256", "content": boost_match.group(3)}],
            "license": LICENSE_MAP.get("boost", "UNKNOWN"),
            "spdx": spdx
        })
    
    # General CPM pattern
    cpm_pattern = re.compile(
        r'CPMAddPackage\(\s*'
        r'NAME\s+(\w+).*?'
        r'(?:GITHUB_REPOSITORY\s+([/\w-]+)|URL\s+"([^"]+)".*?URL_HASH\s+SHA256=(\w+))?.*?'
        r'(?:GIT_TAG\s+([^\s)]+))?.*?'
        r'(?:VERSION\s+([\d.]+))?',
        re.DOTALL
    )
    
    for match in cpm_pattern.finditer(content):
        name = match.group(1)
        if name == "Boost":
            continue
            
        github_repo = match.group(2)
        url = match.group(3)
        sha256 = match.group(4)
        git_tag = match.group(5)
        version = match.group(6) or git_tag.lstrip('v') if git_tag else "unknown"
        
        component = {
            "name": name,
            "version": version.split('-')[0],
            "source": "CPM",
            "license": LICENSE_MAP.get(name.lower(), "UNKNOWN"),
            "spdx": spdx
        }
        
        if github_repo:
            component["purl"] = f"pkg:github/{github_repo}@{version}"
            component["repo"] = f"https://github.com/{github_repo}"
        elif url:
            component["url"] = url
            if sha256:
                component["hashes"] = [{"alg": "SHA256", "content": sha256}]
        
        components.append(component)
    
    return components

def generate_sbom(install_data, cmake_data, deps_data, versions, project_spdx):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {
                "name": "Metalium",
                "version": versions.get("VERSION_NUMERIC", "unknown"),
                "type": "application",
                "purl": f"pkg:github/tenstorrent/tt-metal@{versions.get('VERSION_NUMERIC', '')}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "copyright": "\n".join(project_spdx['copyrights']),
                "evidence": {
                    "licenses": [{
                        "license": {
                            "id": "Apache-2.0",
                            "text": {
                                "contentType": "text/plain",
                                "encoding": "base64",
                                "content": base64.b64encode(
                                    open("LICENSE").read().encode()
                                ).decode()
                            }
                        }
                    }]
                }
            }
        },
        "components": [],
        "dependencies": []
    }
    
    seen_components = set()
    
    def add_component(component):
        key = (component.get('name'), component.get('version'), component.get('purl'))
        if key not in seen_components:
            seen_components.add(key)
            
            # Merge SPDX data safely
            if 'spdx' in component:
                component.setdefault('copyright', "\n".join(component['spdx'].get('copyrights', [])))
                licenses = component.get('licenses', [])
                for lic in component['spdx'].get('licenses', []):
                    licenses.append({"license": {"id": lic}})
                component['licenses'] = licenses
                del component['spdx']
            
            sbom['components'].append(component)
    
    # Add system packages
    ubuntu_codename = versions.get('UBUNTU_CODENAME', 'unknown')
    for list_name in ['UB_RUNTIME_LIST', 'UB_BUILDTIME_LIST', 'UB_BAREMETAL_LIST']:
        for pkg in install_data.get(list_name, []):
            add_component({
                "name": pkg,
                "version": f"ubuntu-{ubuntu_codename}",
                "type": "library",
                "purl": f"pkg:deb/ubuntu/{pkg}?distro=ubuntu-{ubuntu_codename}",
                "source": "install_dependencies.sh",
                "licenses": [{"license": {"id": "UNKNOWN"}}]
            })
    
    # Add special components
    for deb in install_data.get('deb_packages', []):
        add_component({
            "name": deb['name'],
            "version": deb['version'],
            "type": "application",
            "purl": f"pkg:deb/tenstorrent/{deb['name']}@{deb['version']}",
            "source": deb['source'],
            "licenses": [{"license": {"id": LICENSE_MAP.get(deb['name'], "UNKNOWN")}}],
            "spdx": deb.get('spdx', {})
        })
    
    # Add CMake components
    for subdir in cmake_data['subdirectories']:
        if 'dependencies' in subdir['path'] or 'umd' in subdir['path']:
            name = subdir['path'].split('/')[-1]
            add_component({
                "name": name,
                "version": "git-submodule",
                "type": "library",
                "source": f"CMakeLists.txt (add_subdirectory {subdir['path']})",
                "purl": f"pkg:git/{versions.get('PROJECT_URL', 'unknown')}@{name}",
                "licenses": [{"license": {"id": "UNKNOWN"}}],
                "spdx": subdir.get('spdx', {})
            })
    
    # Add CPM dependencies
    for dep in deps_data:
        component = {
            "name": dep["name"],
            "version": dep.get("version", "unknown"),
            "type": "library",
            "source": dep.get("source", "unknown"),
            "purl": dep.get("purl", ""),
            "licenses": [{"license": {"id": dep.get("license", "UNKNOWN")}}],
            "spdx": dep.get("spdx", {})
        }
        if "hashes" in dep:
            component["hashes"] = dep["hashes"]
        add_component(component)
    
    # Add compiler toolchain
    if 'gcc' in install_data:
        add_component({
            "name": "gcc",
            "version": install_data['gcc']['version'],
            "type": "tool",
            "purl": f"pkg:apt/ubuntu/gcc-{install_data['gcc']['version']}",
            "source": "install_dependencies.sh",
            "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]
        })
    
    return sbom

def collect_project_spdx():
    spdx = {
        "copyrights": set(),
        "licenses": set()
    }
    
    for root, _, files in os.walk('.'):
        for file in files:
            if file.endswith(('.cpp', '.hpp', '.c', '.h', '.cmake', 'CMakeLists.txt', '.sh')):
                path = os.path.join(root, file)
                with open(path) as f:
                    content = f.read()
                    headers = parse_spdx_headers(content)
                    spdx['copyrights'].update(headers['copyrights'])
                    spdx['licenses'].update(headers['licenses'])
    
    return spdx

if __name__ == "__main__":
    # Collect project-wide SPDX data
    project_spdx = collect_project_spdx()
    
    # Parse build files
    with open('CMakeLists.txt') as f:
        cmake_content = f.read()
        cmake_data = parse_cmakelists(cmake_content, 'CMakeLists.txt')
    
    with open('install_dependencies.sh') as f:
        install_content = f.read()
        install_data, versions = parse_install_script(install_content)
    
    with open('dependencies/CMakeLists.txt') as f:
        deps_content = f.read()
        deps_data = parse_dependencies_cmakelists(deps_content)
    
    # Generate SBOM
    sbom = generate_sbom(install_data, cmake_data, deps_data, versions, project_spdx)
    
    # Write output
    with open('sbom.cdx.json', 'w') as f:
        json.dump(sbom, f, indent=2, sort_keys=True)
    
    print("Generated compliant SBOM at sbom.cdx.json")
