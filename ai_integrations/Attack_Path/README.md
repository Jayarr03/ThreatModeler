# Attack Path Simulator

Generate high-likelihood attack paths using MITRE ATT&CK framework, ThreatModeler threat intelligence, and OpenAI's language models.

## Phase 1 - Complete ✓

All core components are implemented and production-ready:
- ThreatModeler API client with project search
- MITRE ATT&CK data fetcher with 7-day caching
- OpenAI API wrapper for attack path generation  
- **Parallel processing** for efficient threat analysis
- Colored logging framework
- Command-line interface with multiple options

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

Copy the template and add your API keys:

```bash
cp .env.template .env
```

Edit `.env` and add your credentials:
- `THREATMODELER_API_KEY` - From your ThreatModeler account
- `OPENAI_API_KEY` - From https://platform.openai.com/api-keys
- `THREATMODELER_API_URL` - Your ThreatModeler instance URL

### 3. Run the Simulator

```bash
# Using project name (recommended)
python attack_path_simulator.py --project-name "Your Project Name"

# Or using project GUID
python attack_path_simulator.py --project-guid YOUR_PROJECT_GUID

# List all available projects
python attack_path_simulator.py --list-projects

# Search for projects
python attack_path_simulator.py --search-projects "Azure"
```

## Usage Examples

### Basic Usage

```bash
# Generate attack paths using project name
python attack_path_simulator.py --project-name "Azure Container App"

# Using project GUID
python attack_path_simulator.py --project-guid abc123-def456

# Export as CSV
python attack_path_simulator.py --project-name "My Project" --output-format csv

# Custom output file
python attack_path_simulator.py \
  --project-name "My Project" \
  --output-format json \
  --output-file my_attack_paths.json

# List all available projects
python attack_path_simulator.py --list-projects

# Search for projects by name
python attack_path_simulator.py --search-projects "Container"
```

### Advanced Options

```bash
# Force refresh MITRE data cache
python attack_path_simulator.py \
  --project-guid abc123-def456 \
  --force-refresh-mitre

# Debug logging
python attack_path_simulator.py \
  --project-guid abc123-def456 \
  --log-level DEBUG

# Custom .env file
python attack_path_simulator.py \
  --project-guid abc123-def456 \
  --env-file .env.production
```

## Project Structure

```
Attack_Path/
├── attack_path_simulator.py    # Main application
├── requirements.txt             # Python dependencies
├── .env.template               # Configuration template
├── .env                        # Your configuration (gitignored)
├── README.md                   # This file
├── cache/                      # MITRE ATT&CK data cache
│   └── mitre/
└── output/                     # Generated attack paths
    └── attack_paths_*.json
```

## Features

### ThreatModeler Integration
- **Project Discovery**: List, search, and lookup projects by name or GUID
- Retrieves comprehensive threat data from ThreatModeler projects
- Extracts threat names, descriptions, severities, categories, and statuses
- Fetches component information with types and relationships
- Groups threats by component for better organization

### MITRE ATT&CK Integration
- Downloads latest MITRE ATT&CK STIX data
- Caches data locally (refreshes every 7 days)
- Maps techniques to tactics
- Searchable technique database

### OpenAI Attack Path Generation
- Uses GPT-4 or GPT-3.5-turbo
- **Parallel processing**: Analyzes multiple threats concurrently (default: 8 workers)
- Generates realistic attack sequences
- Provides likelihood scoring with justifications
- Maps attack steps to MITRE techniques
- Thread-safe with real-time progress tracking

### Output Formats
- **JSON**: Structured data including:
  - Project summary with component and threat counts
  - Component list with types
  - Threats grouped by component
  - Generated attack paths with MITRE mappings
  - Analysis statistics
- **CSV**: Flat format for spreadsheet analysis
- **Markdown**: Human-readable reports (coming in Phase 4)

## Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `THREATMODELER_API_URL` | Your ThreatModeler instance URL | Required |
| `THREATMODELER_API_KEY` | API key for authentication | Required |
| `OPENAI_API_KEY` | OpenAI API key | Required |
| `OPENAI_MODEL` | Model to use (gpt-4 or gpt-3.5-turbo) | gpt-4 |
| `OPENAI_MAX_TOKENS` | Max tokens per request | 2000 |
| `OPENAI_TEMPERATURE` | Sampling temperature (0-1) | 0.7 |
| `MITRE_CACHE_EXPIRY_DAYS` | Days before cache refresh | 7 |
| `LOG_LEVEL` | Logging level | INFO |
| `OUTPUT_DIR` | Directory for output files | ./output |
| `MAX_ATTACK_PATHS_PER_THREAT` | Paths to generate per threat | 3 |
| `MIN_LIKELIHOOD_SCORE` | Minimum score to include | 5 |
| `MAX_WORKERS` | **Concurrent OpenAI API calls** | 8 |
| `MAX_THREATS_TO_PROCESS` | **Limit threats (0 = all)** | 0 |

## Next Steps (Phase 2)

Phase 2 will add intelligent threat-to-technique mapping:
- Automated correlation between ThreatModeler threats and MITRE techniques
- Confidence scoring for mappings
- Context-aware technique selection
- Enhanced attack path relevance

## Troubleshooting

### Connection Issues

If you get authentication errors:
1. Verify your API keys in `.env`
2. Check that your ThreatModeler instance URL is correct
3. Ensure you have network access to all APIs

### MITRE Data Download

If MITRE data download fails:
1. Check internet connectivity
2. Try `--force-refresh-mitre` flag
3. Manually download from https://github.com/mitre/cti

### OpenAI Rate Limits

If you hit rate limits:
1. Reduce `MAX_WORKERS` in `.env` (e.g., from 8 to 4)
2. Set `MAX_THREATS_TO_PROCESS` to limit processing (e.g., 20 threats at a time)
3. Reduce `MAX_ATTACK_PATHS_PER_THREAT` in `.env`
4. Consider using gpt-3.5-turbo instead of gpt-4

## Performance & Cost

### Processing Speed
With parallel processing (default 8 workers):
- **Small project** (10 threats): ~1-2 minutes
- **Medium project** (50 threats): ~5-8 minutes  
- **Large project** (100+ threats): ~10-15 minutes

*Processing time depends on OpenAI response time and complexity*

### OpenAI API Costs
Approximate costs (GPT-4):
- **Small project** (10 threats): ~$0.50 - $1.00
- **Medium project** (50 threats): ~$2.50 - $5.00
- **Large project** (100+ threats): ~$5.00 - $10.00

*Costs vary based on model choice and complexity. Use GPT-3.5-turbo for lower costs (~70% cheaper).*

### Tuning Performance
- Increase `MAX_WORKERS` (8-16) for faster processing if your OpenAI tier allows
- Decrease to 2-4 if you hit rate limits
- Test with `MAX_THREATS_TO_PROCESS=10` before running full analysis

## Support

For issues or questions:
- Check [attack_path_project_plan.md](attack_path_project_plan.md) for detailed documentation
- Review logs with `--log-level DEBUG`
- Contact ThreatModeler support for API-related issues

---

**Version**: 1.0.0 (Phase 1)  
**Last Updated**: March 10, 2026
