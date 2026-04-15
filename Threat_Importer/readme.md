# Threat Importer

A suite of Python scripts for bulk-importing threats and security requirements into ThreatModeler projects via the ThreatModeler REST API.

---

## Setup

### Prerequisites

- Python 3.9+
- A ThreatModeler API key

### Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configure credentials

Create a `.env` file in this directory:

```
THREATMODELER_API_URL=https://<your-instance>.threatmodeler.us
THREATMODELER_API_KEY=<your-api-key>
```

---

## Workflow

The recommended end-to-end flow is:

1. **Download all projects** → `threat_models.json`
2. **Inspect diagram nodes** for the target project (optional)
3. **Prepare a threats CSV** with the threats and security requirements to import
4. **Run the import pipeline** — threats and SRs are created in the library and attached to the correct diagram nodes automatically

---

## Scripts

### 1. `download_projects.py`

Downloads all ThreatModeler projects (paginated) and saves them to `threat_models.json`. This file is required by the import pipeline to look up project GUIDs by name.

```bash
python3 download_projects.py
```

**Output:** `threat_models.json`

---

### 2. `download_diagram_nodes.py`

Fetches the diagram nodes (components) for one or all projects. Useful for discovering the exact node names to use as `targetNode` in the CSV.

```bash
# By project name (partial match supported)
python3 download_diagram_nodes.py --project-name "Amey"

# By GUID
python3 download_diagram_nodes.py --guid 8d23668c-1307-4bb0-ba31-dedc085fb92a

# All projects
python3 download_diagram_nodes.py
```

**Output:** `<ProjectName>_diagram_nodes.json` (or `all_diagram_nodes.json` for all)

Only nodes with `IsNode: true` can receive threats. The script output lists all addressable nodes.

---

### 3. `import_threats.py` _(main import pipeline)_

Takes a CSV file of threats and security requirements, then for each row:

1. Looks up the project GUID from `threat_models.json`
2. Fetches the project's diagram nodes
3. Creates each threat as a library entity
4. Creates each security requirement as a library entity and links it to the threat
5. Attaches the threat (with its SRs) to the matching diagram node

```bash
python3 import_threats.py --project-name "Amey" --threats-file sample_threats.csv
```

| Argument | Required | Default | Description |
|---|---|---|---|
| `--project-name` | Yes | — | Project name (exact or partial match) |
| `--threats-file` | Yes | — | Path to the threats CSV file |
| `--projects-file` | No | `threat_models.json` | Path to the downloaded projects file |

---

## Threats CSV Format

Each row represents one threat–SR pair. To attach multiple security requirements to a single threat, repeat the threat columns on additional rows with different `sr*` values. To import a threat with no SR, leave the `sr*` columns blank.

| Column | Required | Description |
|---|---|---|
| `targetNode` | Yes | Exact name of the diagram node (component) to attach the threat to |
| `threatName` | Yes | Name of the threat |
| `threatDescription` | No | HTML description of the threat |
| `threatSeverity` | No | `very high`, `high`, `medium`, `low`, or `very low` (default: `medium`) |
| `libraryId` | No | Library ID to create the threat in (default: `10`) |
| `srName` | No | Name of the security requirement |
| `srDescription` | No | HTML description of the security requirement |
| `srSeverity` | No | Severity of the SR (defaults to threat severity if blank) |
| `srLibraryId` | No | Library ID for the SR (defaults to `libraryId` if blank) |

### Example

```csv
targetNode,threatName,threatDescription,threatSeverity,libraryId,srName,srDescription,srSeverity,srLibraryId
Web Application,SQL Injection,<p>Unsanitized input passed to SQL queries.</p>,high,10,Parameterize All Queries,<p>Use prepared statements for all DB queries.</p>,high,10
Web Application,SQL Injection,<p>Unsanitized input passed to SQL queries.</p>,high,10,Enable WAF,<p>Deploy a web application firewall.</p>,medium,10
EC2 Instance,Exposed SSH Port,<p>SSH port accessible from the internet.</p>,high,10,,,, 
```

- Row 1 and 2: same threat ("SQL Injection") with two different SRs
- Row 3: a threat with no security requirement (blank `sr*` columns)

### Known library IDs

| ID | Library |
|---|---|
| `10` | Corporate | # Your tenant may be different
| `109` | Consulting |
| `114` | Developer |

### Valid severity values

`very high` / `critical`, `high`, `medium`, `low`, `very low`

---

## Utility Scripts

| Script | Purpose |
|---|---|
| `download_departments.py` | Fetches all departments and their IDs → `departments.json` |
| `download_library_threats.py` | Browses existing library threats → `library_threats.json` |
| `create_threat.py` | Standalone script to create a single threat in the library |
| `add_threats.py` | Low-level script to attach threats to a node by explicit GUID and node ID |
