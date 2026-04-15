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
    'X-ThreatModeler-ApiKey': api_key,
    'Content-Type': 'application/json'
})

# API endpoint
url = f"{api_url}/api/project/projects"

PAGE_LIMIT = 100

try:
    all_projects = []
    page = 1
    total = None

    while True:
        body = {
            "pageNumber": page,
            "pageLimit": PAGE_LIMIT,
        }

        response = session.post(url, json=body, verify=False)
        response.raise_for_status()

        data = response.json()

        if not data.get('isSuccess', True):
            print(f"API returned isSuccess=false on page {page}. Response:\n{json.dumps(data, indent=2)}")
            exit(1)

        if total is None:
            total = data.get('total', 0)
            print(f"Total projects to download: {total}")

        projects = data.get('data', [])
        all_projects.extend(projects)
        print(f"Page {page}: fetched {len(projects)} projects ({len(all_projects)}/{total})")

        if len(all_projects) >= total or len(projects) < PAGE_LIMIT:
            break

        page += 1

    # Save all projects to threat_models.json
    with open('threat_models.json', 'w', encoding='utf-8') as f:
        json.dump(all_projects, f, indent=4, ensure_ascii=False)

    print(f"Successfully downloaded {len(all_projects)} projects to threat_models.json")

except requests.exceptions.RequestException as e:
    print(f"Error making API request: {e}")
    exit(1)
except json.JSONDecodeError as e:
    print(f"Error parsing JSON response: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error: {e}")
    exit(1)