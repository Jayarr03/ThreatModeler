import os
import json
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

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

url = f"{api_url}/api/library/getallthreat"

try:
    response = session.get(url, verify=False)
    print(f"HTTP Status: {response.status_code}")
    response.raise_for_status()

    data = response.json()

    if not data.get('isSuccess', True):
        print(f"API returned isSuccess=false:\n{json.dumps(data, indent=2)}")
        exit(1)

    threats = data.get('data', data)

    with open('library_threats.json', 'w', encoding='utf-8') as f:
        json.dump(threats, f, indent=4, ensure_ascii=False)

    count = len(threats) if isinstance(threats, list) else 'N/A'
    print(f"Successfully downloaded {count} library threat(s) to library_threats.json")

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)
