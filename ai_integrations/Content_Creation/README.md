# AI-Driven Threat Modeling System

Automated threat modeling system that analyzes components (hardware or software) and generates security threats, requirements, and test cases using OpenAI GPT-4.

## Quick Start

### 1. Configure Environment

Copy the example environment file and add your OpenAI API key:

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run Threat Modeling

#### Option 1: Test Example (Built-in Hardware Sensor)

```bash
python threat_generator.py --test
```

#### Option 2: Analyze Your Own Component

**Hardware Component Example:**
```bash
python threat_generator.py \
  --name "USB Storage Device" \
  --type hardware \
  --description "USB flash drive with AES-256 encryption, firmware update capability, and hardware root of trust. Interfaces: USB 3.0, internal flash storage."
```

**Software Component Example:**
```bash
python threat_generator.py \
  --name "Payment Processing API" \
  --type software \
  --description "REST API handling credit card transactions. Uses TLS 1.3, JWT authentication, and integrates with external payment gateway. Stores transaction history in PostgreSQL database."
```

## Command-Line Arguments

| Argument | Short | Required | Description |
|----------|-------|----------|-------------|
| `--name` | `-n` | Yes* | Name of the component to analyze |
| `--description` | `-d` | Yes* | Detailed description of the component |
| `--type` | `-t` | Yes* | Component type: `hardware` or `software` |
| `--output` | `-o` | No | Custom output directory (default: `./output/`) |
| `--test` | | No | Run built-in test example |

*Required unless using `--test`

## What It Does

The system runs through 6 functional requirements (FR):

1. **FR-1: Component Input Processing**
   - Extracts technical details: protocols, interfaces, data types, trust boundaries
   - Identifies data flows and potential attack surfaces

2. **FR-2: CWE Applicability Analysis**
   - Analyzes ~110 hardware or ~400 software CWEs
   - Scores relevance (1-10) and filters most applicable
   - Uses batch processing for efficiency

3. **FR-3: Threat Generation**
   - Generates 10 high-value threats
   - Maps to STRIDE categories
   - Validates quality criteria (≥7 high severity, ≥4 STRIDE categories)

4. **FR-4: Security Requirements**
   - Creates security requirements for each threat
   - References industry standards (OWASP, NIST, ISO, PCI-DSS, IEC)
   - Maps severity to requirement priority

5. **FR-5: Test Case Generation**
   - Creates reproducible test cases
   - Includes pass/fail criteria
   - Links to security requirements

6. **FR-6: Database Storage & CSV Export**
   - Stores all data in SQLite database
   - **Exports CSV file (REQUIRED for downstream scripts)**
   - 18-column format matching `test_security_data.csv`

## Output Files

After completion, you'll find:

- **Database**: `threat_model.db` - SQLite database with 6 normalized tables
- **CSV**: `output/<Component_Name>_threat_model.csv` - Required for downstream import scripts

### CSV Schema (18 columns)

```
Library, Component, ComponentDescription, Threat, ThreatDescription, 
Category, Severity, STRIDE, Mitigation, SecurityRequirement, 
SecurityRequirementDescription, Priority, SecurityRequirementCategory, 
Standard, TestCase, TestCaseDescription, Property, PropertyValue
```

## Configuration (.env)

Key environment variables:

```bash
# Required
OPENAI_API_KEY=sk-...

# Optional (with defaults)
OPENAI_MODEL=gpt-4o-mini  # Supports: gpt-4o-mini, gpt-4o, gpt-4-turbo (JSON mode required)
DATABASE_PATH=./threat_model.db
HARDWARE_CWE_LIST=./hardware_cwe_list.csv
SOFTWARE_CWE_LIST=./software_cwe_list.csv
TARGET_THREAT_COUNT=10
MAX_CWE_ANALYSIS=15
OUTPUT_DIRECTORY=./output/
```

**Note**: The system requires models that support JSON mode (structured outputs). Recommended models:
- `gpt-4o-mini` (default, cost-effective)
- `gpt-4o` (faster, higher quality)
- `gpt-4-turbo` (high quality)

Base models like `gpt-4` or `gpt-3.5-turbo` do **not** support JSON mode and will fail.

## Tips for Best Results

### Component Descriptions Should Include:

**Hardware:**
- Communication protocols (UART, I2C, SPI, USB, Ethernet, etc.)
- Interfaces and ports
- Power specifications
- Firmware capabilities
- Security features (encryption, secure boot, etc.)
- Data storage mechanisms

**Software:**
- APIs and endpoints
- Authentication/authorization mechanisms
- External integrations
- Database/storage details
- Network protocols
- Security controls

### Example: Good vs. Minimal Description

❌ **Minimal**: "A temperature sensor"

✅ **Good**: "Industrial IoT temperature sensor (-40°C to 125°C) with UART/I2C communication, 3.3V power, firmware for calibration, EEPROM storage, and network transmission capability"

## Typical Runtime

- **CWE Analysis**: 2-5 minutes (batch processing)
- **Threat Generation**: 3-7 minutes
- **Requirements & Test Cases**: 2-4 minutes
- **Total**: 7-16 minutes per component

Times vary based on component complexity and API response times.

## Troubleshooting

### "OPENAI_API_KEY not configured"
- Ensure `.env` file exists in the same directory as `threat_generator.py`
- Verify your API key is valid and has credits

### "Invalid parameter: 'response_format' of type 'json_object' is not supported with this model"
- Your configured model doesn't support JSON mode
- Update `OPENAI_MODEL` in `.env` to `gpt-4o-mini`, `gpt-4o`, or `gpt-4-turbo`
- Base models like `gpt-4` or `gpt-3.5-turbo` do not support JSON mode

### "No CWEs found applicable"
- Provide more technical details in component description
- Include specific protocols, interfaces, and security concerns

### "Quality criteria not met"
- System automatically retries if threat quality is insufficient
- May need more detailed component description for better threat generation

## Integration with Downstream Scripts

The CSV output is **REQUIRED** for downstream import scripts. The 18-column format matches `test_security_data.csv` exactly and can be directly imported into other systems.

## Support

For issues or questions, check the logs in `threat_modeling.log` for detailed debugging information.
