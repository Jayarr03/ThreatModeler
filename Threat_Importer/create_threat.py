import os
import json
import argparse
import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# Risk level mapping (matches Library_Creator convention)
RISK_LEVELS = {
    'very high': (1, 'Very High'),
    'critical':  (1, 'Very High'),
    'high':      (2, 'High'),
    'medium':    (3, 'Medium'),
    'low':       (4, 'Low'),
    'very low':  (5, 'Very Low'),
}

parser = argparse.ArgumentParser(description='Create a threat in a ThreatModeler library')
parser.add_argument('--library-id', required=True, type=int, help='Library ID to add the threat to')
parser.add_argument('--name', required=True, type=str, help='Threat name')
parser.add_argument('--description', default='', type=str, help='Threat description')
parser.add_argument('--severity', default='medium', type=str,
                    help='Severity: very high, high, medium, low, very low (default: medium)')
parser.add_argument('--labels', default='', type=str, help='Comma-separated labels')
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

# Resolve risk level
risk_id, risk_name = RISK_LEVELS.get(args.severity.strip().lower(), (3, 'Medium'))

threat_data = {
    "id": 0,
    "name": args.name,
    "description": args.description,
    "riskId": risk_id,
    "libraryId": args.library_id,
    "guid": None,
    "labels": args.labels,
    "isHidden": False,
    "isEnableAssociation": False
}

payload = {
    "EntityTypeName": "Threat",
    "Model": json.dumps([threat_data])
}

print(f"Creating threat '{args.name}' in library {args.library_id} (risk: {risk_name})...")

try:
    response = session.post(f"{api_url}/api/diagram/addrecords", json=payload, verify=False)
    print(f"HTTP Status: {response.status_code}")
    response.raise_for_status()

    data = response.json()

    if not data.get('isSuccess', True):
        print(f"API returned isSuccess=false:\n{json.dumps(data, indent=2)}")
        exit(1)

    result = data.get('data', data.get('result'))

    # Extract created threat ID
    threat_id = None
    if isinstance(result, list) and result:
        threat_id = result[0].get('id')
    elif isinstance(result, dict):
        threat_id = result.get('id')
    elif isinstance(result, str):
        threat_id = int(result.strip('[]'))

    print(f"Threat created successfully.")
    print(f"  ID        : {threat_id}")
    print(f"  Name      : {args.name}")
    print(f"  LibraryId : {args.library_id}")
    print(f"  Risk      : {risk_name}")
    print()
    print("Use these values in your threats payload for add_threats.py:")
    print(json.dumps([{
        "id": threat_id,
        "name": args.name,
        "riskId": risk_id,
        "riskName": risk_name,
        "libraryId": args.library_id,
        "isHidden": False,
        "securityRequirements": []
    }], indent=2))

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)
