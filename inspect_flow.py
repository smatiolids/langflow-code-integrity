#!/usr/bin/env python3
"""
Script to check if a Langflow flow JSON file was changed by the user.

This script:
1. Generates a hash from the JSON document
2. Finds all "code" attributes in the JSON
3. Generates hashes of the code content
4. Optionally compares with a reference/validated file
5. Reports if changes were detected
"""

import json
import hashlib
import argparse
import re
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import requests

# TO-DO: Add more components here
source_files = {"ChatInput": "input_output/chat.py",
                "ChatOutput": "input_output/chat_output.py", 
                "AgentComponent": "agents/agent.py"}

SOURCE_FILES = "https://raw.githubusercontent.com/langflow-ai/langflow"

# Langflow is changing where the components code are located in the source code.
# This is a dictionary of the versions and the paths to the components code.
SOURCE_VERSION_PATH = {
    "1.6.0": "src/backend/base/langflow/components",
    "1.7.0": "src/lfx/src/lfx/components",
}

def get_source_file(version: str, component_name: str) -> str:
    """
    Get the source file for a given component name and version.
    
    Finds the matching key in SOURCE_VERSION_PATH based on major.minor version.
    Versions are numbered as n.n.nnn (e.g., "1.6.3", "1.7.0").
    """
    # Extract major.minor version (e.g., "1.6.3" -> "1.6")
    version_parts = version.split('.')
    if len(version_parts) < 2:
        # If version format is unexpected, try to use as-is
        matching_key = version
    else:
        major_minor = f"{version_parts[0]}.{version_parts[1]}"
        # Find the key in SOURCE_VERSION_PATH that starts with major.minor
        matching_key = None
        for key in SOURCE_VERSION_PATH.keys():
            if key.startswith(major_minor):
                matching_key = key
                break
        
        # If no match found, use the first available key as fallback
        if matching_key is None:
            matching_key = list(SOURCE_VERSION_PATH.keys())[0] if SOURCE_VERSION_PATH else ""
            
    component_path = source_files.get(component_name, "")
    
    if matching_key and matching_key in SOURCE_VERSION_PATH:
        return f"{SOURCE_FILES}/{version}/{SOURCE_VERSION_PATH[matching_key]}/{component_path}"
    else:
        return ""

def generate_hash(data: str | bytes) -> str:
    """Generate SHA256 hash of the given data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def normalize_code(code: str) -> str:
    """
    Normalize code string for consistent comparison.
    
    This function normalizes code by:
    - Normalizing line endings (convert \\r\\n and \\r to \\n)
    - Removing trailing whitespace from lines
    - Ensuring consistent newline representation
    
    This ensures that code from JSON and code from source files
    are compared fairly, accounting for formatting differences.
    """
    if not isinstance(code, str):
        return ""
    
    # Normalize line endings: convert \r\n and \r to \n
    normalized = code.replace('\r\n', '\n').replace('\r', '\n')
    
    # Remove trailing whitespace from each line
    lines = normalized.split('\n')
    normalized_lines = [line.rstrip() for line in lines]
    
    # Join back with normalized newlines
    normalized = '\n'.join(normalized_lines)
    
    # Ensure the string ends with a newline if it's not empty
    # This matches common file representation
    if normalized and not normalized.endswith('\n'):
        normalized += '\n'
    
    return normalized


def compare_code_line_by_line(code1: str, code2: str) -> Dict[str, Any]:
    """
    Compare two code strings line by line and return differences.
    
    Returns a dictionary with:
    - differences: List of dicts with line_number, code1_line, code2_line, type
    - total_lines_code1: Total number of lines in code1
    - total_lines_code2: Total number of lines in code2
    - match: Boolean indicating if codes match exactly
    """
    if not code1 or not code2:
        return {
            "differences": [],
            "total_lines_code1": 0,
            "total_lines_code2": 0,
            "match": code1 == code2
        }
    
    lines1 = code1.split('\n')
    lines2 = code2.split('\n')
    
    differences = []
    max_lines = max(len(lines1), len(lines2))
    
    for i in range(max_lines):
        line1 = lines1[i] if i < len(lines1) else None
        line2 = lines2[i] if i < len(lines2) else None
        
        if line1 != line2:
            diff_type = "modified"
            if line1 is None:
                diff_type = "added_in_code2"
            elif line2 is None:
                diff_type = "added_in_code1"
            
            differences.append({
                "line_number": i + 1,  # 1-indexed for readability
                "code1_line": line1 if line1 is not None else "<missing>",
                "code2_line": line2 if line2 is not None else "<missing>",
                "type": diff_type
            })
    
    return {
        "differences": differences,
        "total_lines_code1": len(lines1),
        "total_lines_code2": len(lines2),
        "match": len(differences) == 0
    }


def extract_class_name(code: str) -> str:
    """
    Extract the class name from Python code.

    Looks for class definitions in the format:
    - class ClassName:
    - class ClassName(BaseClass):
    - class ClassName(BaseClass1, BaseClass2):

    Returns the first class name found, or empty string if none found.
    """
    if not isinstance(code, str):
        return ""

    # Pattern to match class definitions
    # Matches: class ClassName: or class ClassName(BaseClass):
    pattern = r'^class\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:'

    for line in code.split('\n'):
        # Strip leading whitespace for matching
        stripped_line = line.lstrip()
        match = re.match(pattern, stripped_line)
        if match:
            return match.group(1)

    return ""


def find_code_attributes(
    obj: Any,
    path: str = "",
    component_id: str = "",
    component_name: str = "",
    last_tested_version: str = ""
) -> List[Dict[str, Any]]:
    """
    Recursively find all 'code' attributes in the JSON structure.

    Tracks component_id from the 'data' level and component_name from the 'node' level.

    Returns a list of dictionaries with code information.
    """
    code_attributes = []

    if isinstance(obj, dict):
        # Track component_id when we encounter a 'data' object with an 'id' field
        if "id" in obj and isinstance(obj.get("id"), str):
            component_id = obj.get("id", "")

        # Track component_name when we encounter a 'node' object with a 'display_name' field
        if "display_name" in obj and isinstance(obj.get("display_name"), str):
            component_name = obj.get("display_name", "")

        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else key

            # Check if this is a 'code' attribute with a 'value' field
            if key == "code" and isinstance(value, dict) and "value" in value:
                code_value = value.get("value", "")
                if isinstance(code_value, str):
                    class_name = extract_class_name(code_value)
                    # Normalize code from JSON for consistent hashing
                    normalized_code = normalize_code(code_value)
                    code_hash = generate_hash(normalized_code)
                    source_file_url = get_source_file(last_tested_version, class_name)
                    source_code = ""
                    normalized_source = ""
                    source_code_hash = ""
                    
                    if source_file_url:
                        try:
                            print(f"Source File URL: {source_file_url}")
                            request_response = requests.get(source_file_url, timeout=10)
                            if request_response.status_code == 200:
                                source_code = request_response.text
                                normalized_source = normalize_code(source_code)
                                source_code_hash = generate_hash(normalized_source)
                            else:
                                print(f"Warning: Failed to download source file. Status code: {request_response.status_code}")
                        except requests.RequestException as e:
                            print(f"Warning: Error downloading source file: {e}")
                    else:
                        print(f"Warning: No source file URL found for {class_name} version {last_tested_version}")
                        
                    # Compare code line by line if source file exists
                    line_diff = None
                    if normalized_source:
                        line_diff = compare_code_line_by_line(normalized_code, normalized_source)
                        
                    code_attributes.append({
                        "component_id": component_id,
                        "component_name": component_name,
                        "class_name": class_name,
                        "last_tested_version": last_tested_version,
                        "path": current_path,
                        "code_value": code_value,
                        "code_hash": code_hash,
                        "source_file": source_file_url,
                        "source_code_hash": source_code_hash,
                        "hash_match": code_hash == source_code_hash if source_code_hash else False,
                        "code_match": normalized_code == normalized_source if normalized_source else False
                    })

            # Recursively search nested structures, passing along the tracked values
            code_attributes.extend(
                find_code_attributes(
                    value, current_path, component_id, component_name, last_tested_version)
            )

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            current_path = f"{path}[{idx}]"
            code_attributes.extend(
                find_code_attributes(
                    item, current_path, component_id, component_name, last_tested_version)
            )

    return code_attributes


def extract_code_hashes(flow_data: Dict[str, Any], last_tested_version: str = "") -> List[Dict[str, Any]]:
    """
    Extract all code attributes and generate hashes for each.

    Returns a list of dictionaries with code information including hashes.
    """
    code_attributes = find_code_attributes(
        flow_data, last_tested_version=last_tested_version)
    return code_attributes


def analyze_flow(json_file: Path) -> Dict[str, Any]:
    """
    Analyze a Langflow flow JSON file.

    Returns a dictionary with:
    - code_attributes: List of dictionaries with code information (id, name, path, hash)
    - code_count: Number of code attributes found
    - flow_data: The parsed JSON data
    """
    with open(json_file, 'r', encoding='utf-8') as f:
        flow_data = json.load(f)

    # Extract last_tested_version from root of JSON
    last_tested_version = flow_data.get("last_tested_version", "")

    # Extract and hash all code attributes
    code_attributes = extract_code_hashes(
        flow_data, last_tested_version=last_tested_version)

    return {
        'code_attributes': code_attributes,
        'code_count': len(code_attributes),
        # 'flow_data': flow_data
    }


def main():
    parser = argparse.ArgumentParser(
        description='Check if a Langflow flow JSON file was changed by the user',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single file
  python check_flow.py flow.json
  
  # Compare with a reference file
  python check_flow.py flow.json --reference reference_flow.json
  
  # Verbose output
  python check_flow.py flow.json --reference reference_flow.json --verbose
        """
    )

    parser.add_argument(
        'flow_file',
        type=Path,
        help='Path to the Langflow flow JSON file to check'
    )

    args = parser.parse_args()

    # Validate input file
    if not args.flow_file.exists():
        print(f"Error: File not found: {args.flow_file}")
        return 1

    # Generate report
    try:
        report = analyze_flow(args.flow_file)

        # Print report in a readable format
        print("=" * 80)
        print("Langflow Flow Analysis Report")
        print("=" * 80)
        print(f"\nFile: {args.flow_file}")
        print(f"Code Attributes Found: {report['code_count']}")
        

        if report['code_count'] > 0:
            print("\n" + "-" * 80)
            print("Code Attributes:")
            print("-" * 80)
            for attr in report['code_attributes']:
                print(f"\nComponent ID: {attr['component_id']}")
                print(f"Component Name: {attr['component_name']}")
                if attr.get('class_name'):
                    print(f"Class Name: {attr['class_name']}")
                if attr.get('last_tested_version'):
                    print(
                        f"Last Tested Version: {attr['last_tested_version']}")
                print(f"Path: {attr['path']}")
                print(f"Code Hash: {attr['code_hash']}")
                print(f"Source File: {attr['source_file']}")
                print(f"Source Code Hash: {attr['source_code_hash']}")
                print(f"Hash Match: {attr['hash_match']}")
                print(f"Code Match: {attr['code_match']}")
                
        print("\n" + "=" * 80)

        components_with_changes = [attr for attr in report['code_attributes'] if not attr['code_match']]
        if components_with_changes:
            print("\n" + "-" * 80)
            print("Components with Changes:")
            print("-" * 80)
            for attr in components_with_changes:
                print(f"\nComponent ID: {attr['component_id']} - {attr['component_name']}")
        else:
            print("No components with changes found.")
            
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == '__main__':
    exit(main())
