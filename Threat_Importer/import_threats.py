import os
import csv
import json
import argparse
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

RISK_LEVELS = {
    'very high': (1, 'Very High'),
    'critical':  (1, 'Very High'),
    'high':      (2, 'High'),
    'medium':    (3, 'Medium'),
    'low':       (4, 'Low'),
    'very low':  (5, 'Very Low'),
}

parser = argparse.ArgumentParser(
    description='Import threats to ThreatModeler diagram nodes by component name'
)
parser.add_argument('--project-name', required=True, type=str,
                    help='Friendly project name (matched against threat_models.json)')
parser.add_argument('--threats-file', required=True, type=str,
                    help='Path to JSON file with threats. Each entry must have a "targetNode" field.')
parser.add_argument('--projects-file', default='threat_models.json', type=str,
                    help='Path to projects file (default: threat_models.json)')
args = parser.parse_args()

api_url = os.getenv('THREATMODELER_API_URL')
api_key = os.getenv('THREATMODELER_API_KEY')

if not api_key:
    raise ValueError("THREATMODELER_API_KEY not found in environment variables")

session = requests.Session()
session.headers.update({
    'Accept-Language': 'en',
    'X-ThreatModeler-ApiKey': api_key,
    'Content-Type': 'application/json'
})

def create_threat(name, description, library_id, severity):
    """Create a threat in the library and return its id and riskId."""
    risk_id, risk_name = RISK_LEVELS.get(severity.strip().lower(), (3, 'Medium'))
    threat_data = {
        "id": 0,
        "name": name,
        "description": description,
        "riskId": risk_id,
        "libraryId": library_id,
        "guid": None,
        "labels": "",
        "isHidden": False,
        "isEnableAssociation": False
    }
    payload = {
        "EntityTypeName": "Threat",
        "Model": json.dumps([threat_data])
    }
    resp = session.post(f"{api_url}/api/diagram/addrecords", json=payload, verify=False)
    resp.raise_for_status()
    data = resp.json()
    if not data.get('isSuccess', True):
        raise RuntimeError(f"Failed to create threat '{name}': {data.get('message')}")
    result = data.get('data', data.get('result'))
    if isinstance(result, list) and result:
        threat_id = result[0].get('id')
    elif isinstance(result, dict):
        threat_id = result.get('id')
    elif isinstance(result, str):
        threat_id = int(result.strip('[]'))
    else:
        raise RuntimeError(f"Unexpected response creating threat '{name}': {data}")
    return threat_id, risk_id, risk_name


def create_security_requirements(threat_id, threat_name, threat_risk_id, threat_risk_name,
                                  library_id, sr_entries):
    """Create security requirements as library entities, link them to the threat, and return them."""
    if not sr_entries:
        return []

    created_srs = []
    for sr in sr_entries:
        sr_risk_id, sr_risk_name = RISK_LEVELS.get(
            sr.get('severity', '').strip().lower(), (threat_risk_id, threat_risk_name)
        )
        sr_lib_id = sr.get('libraryId', library_id)

        # Step 1: Create the SR as a library entity (same pattern as threats)
        sr_data = {
            "id": 0,
            "name": sr.get('name'),
            "description": sr.get('description', ''),
            "riskId": sr_risk_id,
            "riskName": sr_risk_name,
            "libraryId": sr_lib_id,
            "labels": sr.get('labels', ''),
            "isHidden": False,
            "isEnableAssociation": False,
            "isCompensatingControl": False
        }
        create_payload = {
            "EntityTypeName": "SecurityRequirement",
            "Model": json.dumps([sr_data])
        }
        resp = session.post(f"{api_url}/api/diagram/addrecords", json=create_payload, verify=False)
        resp.raise_for_status()
        data = resp.json()
        if not data.get('isSuccess', True):
            raise RuntimeError(f"Failed to create SR '{sr.get('name')}': {data.get('message')}")

        result = data.get('data', data.get('result'))
        if isinstance(result, list) and result:
            sr_id = result[0].get('id')
        elif isinstance(result, dict):
            sr_id = result.get('id')
        elif isinstance(result, str):
            sr_id = int(result.strip('[]'))
        else:
            raise RuntimeError(f"Unexpected response creating SR '{sr.get('name')}': {data}")

        created_srs.append({
            "id": sr_id,
            "name": sr.get('name'),
            "description": sr.get('description', ''),
            "riskId": sr_risk_id,
            "riskName": sr_risk_name,
            "libraryId": sr_lib_id,
            "labels": sr.get('labels', ''),
            "isHidden": False,
            "isEnableAssociation": False,
            "isCompensatingControl": False
        })
        print(f"      ✓ Created SR '{sr.get('name')}' with id: {sr_id}")

    # Step 2: Link all SRs to the threat
    link_payload = {
        "id": threat_id,
        "name": threat_name,
        "riskId": threat_risk_id,
        "riskName": threat_risk_name,
        "libraryId": library_id,
        "securityRequirements": created_srs
    }
    link_resp = session.post(
        f"{api_url}/api/library/SaveThreatSecurityRequirementsTestcases",
        json=link_payload,
        verify=False
    )
    link_resp.raise_for_status()
    link_data = link_resp.json()
    if not link_data.get('isSuccess', True):
        raise RuntimeError(f"Failed to link security requirements: {link_data.get('message')}")

    return created_srs

# ── Step 1: Find project by name ──────────────────────────────────────────────
print(f"Looking up project '{args.project_name}' in {args.projects_file}...")

with open(args.projects_file, 'r', encoding='utf-8') as f:
    projects = json.load(f)

matches = [p for p in projects if p.get('name', '').lower() == args.project_name.lower()]

if not matches:
    # Try partial match
    matches = [p for p in projects if args.project_name.lower() in p.get('name', '').lower()]

if not matches:
    print(f"ERROR: No project found matching '{args.project_name}'.")
    print("Available projects (first 20):")
    for p in projects[:20]:
        print(f"  - {p.get('name')} (id: {p.get('id')})")
    exit(1)

if len(matches) > 1:
    print(f"Multiple projects matched '{args.project_name}':")
    for p in matches:
        print(f"  - {p.get('name')} (id: {p.get('id')}, guid: {p.get('guid')})")
    print("Please use a more specific name.")
    exit(1)

project = matches[0]
guid = project['guid']
print(f"Found project: '{project['name']}' (id: {project['id']}, guid: {guid})")

# ── Step 2: Fetch diagram nodes ───────────────────────────────────────────────
print(f"\nFetching diagram nodes...")
response = session.get(f"{api_url}/api/diagram/{guid}", verify=False)
response.raise_for_status()
diagram_data = response.json()

# Extract nodeDataArray
node_array = []
if isinstance(diagram_data, list) and diagram_data:
    inner = diagram_data[0]
    node_array = inner.get('Data', {}).get('Model', {}).get('nodeDataArray', [])
elif isinstance(diagram_data, dict):
    node_array = diagram_data.get('Data', {}).get('Model', {}).get('nodeDataArray', [])

# Build name -> node map (IsNode=true only)
node_map = {}
for node in node_array:
    if node.get('IsNode', False):
        name = node.get('Name', '').strip()
        if name:
            node_map[name.lower()] = node

print(f"Found {len(node_map)} addressable node(s): {[n.get('Name') for n in node_array if n.get('IsNode')]}")

# ── Step 3: Load threats file ─────────────────────────────────────────────────
threat_entries = []
_threat_index: dict[tuple, int] = {}  # (targetNode, threatName) -> index in threat_entries

with open(args.threats_file, 'r', encoding='utf-8', newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        target = row.get('targetNode', '').strip()
        name = row.get('threatName', '').strip()
        if not target or not name:
            continue
        key = (target.lower(), name.lower())
        if key not in _threat_index:
            _threat_index[key] = len(threat_entries)
            threat_entries.append({
                'targetNode': target,
                'name': name,
                'description': row.get('threatDescription', '').strip(),
                'severity': row.get('threatSeverity', 'medium').strip(),
                'libraryId': int(row.get('libraryId', 10) or 10),
                'securityRequirements': []
            })
        entry = threat_entries[_threat_index[key]]
        sr_name = row.get('srName', '').strip()
        if sr_name:
            entry['securityRequirements'].append({
                'name': sr_name,
                'description': row.get('srDescription', '').strip(),
                'severity': row.get('srSeverity', '').strip(),
                'libraryId': int(row.get('srLibraryId', entry['libraryId']) or entry['libraryId'])
            })

# ── Step 4: Match & import ────────────────────────────────────────────────────
print(f"\nProcessing {len(threat_entries)} threat entry(s)...\n")

# Group threats by targetNode
groups: dict[str, list] = {}
unmatched = []

for entry in threat_entries:
    target = entry.get('targetNode', '').strip()
    if not target:
        print(f"  WARNING: Threat '{entry.get('name')}' has no 'targetNode' field — skipping.")
        unmatched.append({'reason': 'No targetNode field', 'threat': entry})
        continue

    node = node_map.get(target.lower())
    if not node:
        print(f"  NO MATCH: No node named '{target}' found in diagram.")
        unmatched.append({'reason': f"No node named '{target}'", 'threat': entry})
        continue

    # Auto-create threat in library if id is missing
    if not entry.get('id'):
        name = entry.get('name', 'Unnamed Threat')
        library_id = entry.get('libraryId', 10)
        severity = entry.get('severity', 'medium')
        description = entry.get('description', '')
        print(f"  Creating library threat '{name}'...")
        try:
            threat_id, risk_id, risk_name = create_threat(name, description, library_id, severity)
            entry['id'] = threat_id
            entry['riskId'] = risk_id
            entry['riskName'] = risk_name
            entry['isHidden'] = entry.get('isHidden', False)
            print(f"    ✓ Created with id: {threat_id}")

            # Create and link security requirements if provided
            sr_entries = entry.get('securityRequirements', [])
            if sr_entries:
                print(f"    Creating {len(sr_entries)} security requirement(s)...")
                try:
                    saved_srs = create_security_requirements(
                        threat_id, name, risk_id, risk_name, library_id, sr_entries
                    )
                    # Build the SR list for the add_threats payload
                    entry['securityRequirements'] = [
                        {
                            'id': sr.get('id', 0),
                            'name': sr.get('name'),
                            'libraryId': sr.get('libraryId', library_id),
                            'isHidden': False
                        }
                        for sr in saved_srs
                    ]
                    print(f"    ✓ Security requirements saved")
                except Exception as e:
                    print(f"    ⚠ Security requirements failed: {e} (threat will still be added)")
                    entry['securityRequirements'] = []
        except Exception as e:
            print(f"    ✗ Failed to create threat: {e}")
            unmatched.append({'reason': str(e), 'threat': entry})
            continue

    groups.setdefault(target, []).append(entry)

# Post each group to the correct node
success_count = 0
fail_count = 0

for node_name, threats in groups.items():
    node = node_map[node_name.lower()]
    node_id = node.get('Id')

    # Strip targetNode before sending to API
    payload = [{k: v for k, v in t.items() if k != 'targetNode'} for t in threats]

    print(f"  Adding {len(payload)} threat(s) to node '{node_name}' (Id: {node_id})...")

    resp = session.post(
        f"{api_url}/api/diagramaddthreatnodeexternal/{guid}/{node_id}",
        json=payload,
        verify=False
    )

    if resp.status_code == 200:
        data = resp.json()
        if data.get('isSuccess', False):
            print(f"    ✓ Success")
            success_count += len(payload)
        else:
            print(f"    ✗ API error: {data.get('message', 'Unknown error')}")
            fail_count += len(payload)
    else:
        print(f"    ✗ HTTP {resp.status_code}: {resp.text[:200]}")
        fail_count += len(payload)

# ── Summary ───────────────────────────────────────────────────────────────────
print(f"\n{'─'*50}")
print(f"Done.")
print(f"  ✓ Successfully added : {success_count} threat(s)")
print(f"  ✗ Failed             : {fail_count} threat(s)")
if unmatched:
    print(f"  ⚠ Unmatched entries  : {len(unmatched)}")
    for u in unmatched:
        print(f"    - {u['threat'].get('name', '?')} → {u['reason']}")
