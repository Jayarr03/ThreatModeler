import os
import json
import argparse
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

parser = argparse.ArgumentParser(description='Add threats to a diagram node in ThreatModeler')
parser.add_argument('--guid', required=True, type=str, help='Project GUID')
parser.add_argument('--node-id', required=True, type=int, help='Diagram node ID (NodeId from diagram_nodes.json)')
parser.add_argument('--threats-file', required=True, type=str, help='Path to a JSON file containing a list of BriefThreatDetailsModel objects to add')
args = parser.parse_args()

# Get API configuration
api_url = os.getenv('THREATMODELER_API_URL')
api_key = os.getenv('THREATMODELER_API_KEY')

if not api_key:
    raise ValueError("THREATMODELER_API_KEY not found in environment variables")

# Load threats payload from file
with open(args.threats_file, 'r', encoding='utf-8') as f:
    threats = json.load(f)

if not isinstance(threats, list):
    print("ERROR: Threats file must contain a JSON array of threat objects.")
    exit(1)

print(f"Loaded {len(threats)} threat(s) from {args.threats_file}")
print(f"Target project GUID : {args.guid}")
print(f"Target node ID      : {args.node_id}")

# Set up requests session with headers
session = requests.Session()
session.headers.update({
    'Accept-Language': 'en',
    'X-ThreatModeler-ApiKey': api_key,
    'Content-Type': 'application/json'
})

url = f"{api_url}/api/diagramaddthreatnodeexternal/{args.guid}/{args.node_id}"

try:
    response = session.post(url, json=threats, verify=False)
    print(f"HTTP Status: {response.status_code}")
    response.raise_for_status()

    data = response.json()

    if not data.get('isSuccess', True):
        print(f"API returned isSuccess=false:\n{json.dumps(data, indent=2)}")
        exit(1)

    print("Threats added successfully.")
    print(json.dumps(data, indent=2))

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)
