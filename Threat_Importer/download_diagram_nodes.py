import os
import json
import argparse
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

parser = argparse.ArgumentParser(description='Download diagram nodes for ThreatModeler projects')
parser.add_argument('--project-id', type=int, help='Filter by a specific project ID')
parser.add_argument('--guid', type=str, help='Filter by a specific project GUID')
parser.add_argument('--project-name', type=str, help='Filter by project name (case-insensitive, partial match supported)')
args = parser.parse_args()

# Get API configuration
api_url = os.getenv('THREATMODELER_API_URL')
api_key = os.getenv('THREATMODELER_API_KEY')

if not api_key:
    raise ValueError("THREATMODELER_API_KEY not found in environment variables")

# Set up requests session with headers
session = requests.Session()
session.headers.update({
    'Accept-Language': 'en',
    'X-ThreatModeler-ApiKey': api_key
})

# Load projects from threat_models.json
with open('threat_models.json', 'r', encoding='utf-8') as f:
    projects = json.load(f)

print(f"Loaded {len(projects)} projects from threat_models.json")

# Apply filters
if args.project_id:
    projects = [p for p in projects if p.get('id') == args.project_id]
    print(f"Filtered to project ID {args.project_id}: {len(projects)} match(es)")
elif args.guid:
    projects = [p for p in projects if p.get('guid', '').lower() == args.guid.lower()]
    print(f"Filtered to GUID {args.guid}: {len(projects)} match(es)")
elif args.project_name:
    # Try exact match first, then partial
    exact = [p for p in projects if p.get('name', '').lower() == args.project_name.lower()]
    projects = exact if exact else [p for p in projects if args.project_name.lower() in p.get('name', '').lower()]
    print(f"Filtered to project name '{args.project_name}': {len(projects)} match(es)")
    if len(projects) > 1:
        print("Multiple matches found:")
        for p in projects:
            print(f"  - {p.get('name')} (id: {p.get('id')}, guid: {p.get('guid')})")
        print("Use --guid or --project-id to narrow down.")
        exit(1)

if not projects:
    print("No matching projects found. Exiting.")
    exit(1)

all_diagrams = []
failed = []

for i, project in enumerate(projects):
    guid = project.get('guid')
    name = project.get('name', 'Unknown')

    if not guid:
        print(f"  [{i+1}/{len(projects)}] Skipping '{name}' — no GUID")
        continue

    try:
        response = session.get(f"{api_url}/api/diagram/{guid}", verify=False)
        response.raise_for_status()
        data = response.json()

        nodes = []
        # The response is a diagram object; extract node-like components
        if isinstance(data, list):
            nodes = data
        elif isinstance(data, dict):
            # Some responses wrap data in a 'data' key
            nodes = data.get('data', data.get('nodes', [data]))

        all_diagrams.append({
            'projectGuid': guid,
            'projectName': name,
            'projectId': project.get('id'),
            'nodes': nodes
        })

        print(f"  [{i+1}/{len(projects)}] '{name}' — {len(nodes)} node(s)")

    except requests.exceptions.RequestException as e:
        print(f"  [{i+1}/{len(projects)}] ERROR '{name}': {e}")
        failed.append({'guid': guid, 'name': name, 'error': str(e)})

# Save results
import re

if len(all_diagrams) == 1:
    safe_name = re.sub(r'[^\w\-]', '_', all_diagrams[0]['projectName']).strip('_')
    output_file = f"{safe_name}_diagram_nodes.json"
else:
    output_file = "all_diagram_nodes.json"

with open(output_file, 'w', encoding='utf-8') as f:
    json.dump(all_diagrams, f, indent=4, ensure_ascii=False)

print(f"\nDone. Saved diagram nodes for {len(all_diagrams)} projects to {output_file}")

if failed:
    print(f"Failed to fetch {len(failed)} project(s):")
    for f_item in failed:
        print(f"  - {f_item['name']} ({f_item['guid']}): {f_item['error']}")
