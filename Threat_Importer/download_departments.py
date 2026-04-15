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

# API endpoint
url = f"{api_url}/api/departments"

try:
    # Make the GET request
    response = session.get(url, verify=False)  # verify=False as in existing scripts
    response.raise_for_status()

    # Get the JSON data
    data = response.json()

    # Save to departments.json
    with open('departments.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print("Successfully downloaded departments to departments.json")

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)