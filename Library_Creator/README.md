# ThreatModeler Security Content Loader

A Python tool for importing security content (Components, Threats, Security Requirements, Test Cases, and their relationships) from CSV files into ThreatModeler libraries.

## Features

- **CSV Validation**: Validates CSV structure and checks for missing required columns before import
- **Relationship Management**: Automatically creates and links Components → Threats → Security Requirements → Test Cases
- **Entity Deduplication**: Caches entities to avoid creating duplicates within a single import session
- **Metadata Support**: Handles threat severity, categories, STRIDE classification, security requirement priorities, and compliance standards
- **Property Linking**: Supports linking property options to threats (when properties exist in the library)
- **Dry Run Mode**: Validate CSV and preview operations without making changes
- **Flexible Import**: Supports both relationship-based imports and simple entity-only imports
- **Error Handling**: Comprehensive error reporting with detailed validation messages

## Prerequisites

- Python 3.7 or higher
- ThreatModeler API access with valid API key
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone or download this repository

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Create a `.env` file in the project directory with your ThreatModeler credentials:
   ```env
   THREATMODELER_BASE_URL=https://your-instance.threatmodeler.com
   THREATMODELER_API_KEY=your-api-key-here
   ACCEPT_LANGUAGE=en
   API_PATH_PREFIX=
   ```

## CSV Format

### Relationship-Based Import (Recommended)

This format creates entities and their relationships in a single CSV file.

#### Required Columns
- `Library` - Library name where entities will be created #important, this library needs to exist in ThreatModel aand cannot be a default read-only library. 
- `Component` - Component name
- `Threat` - Threat name
- `SecurityRequirement` - Security requirement name

#### Optional Columns

**Descriptions:**
- `ComponentDescription` - Component description
- `ThreatDescription` - Threat description
- `SecurityRequirementDescription` - Security requirement description
- `TestCaseDescription` - Test case description

**Threat Metadata:**
- `Category` or `ThreatCategory` - Threat category (e.g., "Injection", "Authentication")
- `Severity` or `ThreatSeverity` - Severity level (Critical, High, Medium, Low, Very Low)
- `STRIDE` - STRIDE classification (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- `Mitigation` - Mitigation guidance

**Security Requirement Metadata:**
- `Priority` or `SecurityRequirementPriority` - Priority level (Critical, High, Medium, Low)
- `SecurityRequirementCategory` or `SRCategory` - Security requirement category
- `Standard` or `ComplianceStandard` - Compliance standard reference (e.g., "OWASP ASVS 5.3")

**Test Cases:**
- `TestCase` - Test case name
- `TestCaseDescription` - Test case description

**Properties:**
- `Property` - Property name (must exist in the library)
- `PropertyValue` - Property option/value (must exist for the property)

#### Example CSV Format

```csv
Library,Component,ComponentDescription,Threat,ThreatDescription,Category,Severity,STRIDE,SecurityRequirement,Priority,Standard,TestCase
Security Engineering,Web Application,Public-facing web portal,SQL Injection,Attacker injects malicious SQL code,Injection,Critical,Tampering,Use Parameterized Queries,Critical,OWASP ASVS 5.3.1,Test SQL Injection Vectors
Security Engineering,Web Application,Public-facing web portal,Cross-Site Scripting (XSS),Malicious scripts injected into web pages,Injection,High,Tampering,Sanitize User Inputs,High,OWASP ASVS 5.1.3,Test XSS Attack Scenarios
Security Engineering,Authentication Service,Handles user login,Broken Authentication,Authentication mechanisms compromised,Authentication,Critical,Spoofing,Implement Multi-Factor Authentication,Critical,NIST 800-63B,Test MFA Bypass Attempts
```

### Simple Entity Import (Legacy)

For loading a single entity type without relationships, you can use a simple CSV with custom column mappings.

Example for threats only:
```csv
Name,Description,Category,Severity,STRIDE,Mitigation
SQL Injection,An attacker can inject malicious SQL code,Injection,High,Tampering,Use parameterized queries
Cross-Site Scripting (XSS),Malicious scripts injected into trusted websites,Injection,High,Tampering,Sanitize all user inputs
```

## Usage

### 1. Validate CSV Structure

Before importing, validate your CSV file to check for missing columns and structural issues:

```bash
python3 load_security_content.py --validate your_file.csv
```

This will display a detailed validation report showing:
- File statistics (total columns, rows)
- Columns present vs. required/missing
- Warnings about empty columns or rows
- Errors that must be fixed before import

### 2. List Available Libraries

To see which libraries are available in your ThreatModeler instance:

```bash
python3 load_security_content.py --list-libraries
```

### 3. List Available Entity Types

To see all entity types supported by the API:

```bash
python3 load_security_content.py --list-entity-types
```

### 4. Import with Relationships (Recommended)

Import security content with full relationship support:

```bash
python3 load_security_content.py --csv-relationships security_data.csv
```

### 5. Dry Run

Test the import without creating any entities or relationships:

```bash
python3 load_security_content.py --csv-relationships security_data.csv --dry-run
```

### 6. Simple Entity Import (Legacy)

Import a single entity type without relationships:

```bash
python3 load_security_content.py \
  --csv threats.csv \
  --library-id 106 \
  --entity-type "Threat" \
  --map "Name=name" \
  --map "Description=description" \
  --map "Severity=riskName"
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--validate CSV_FILE` | Validate CSV file structure without loading data |
| `--list-libraries` | List all available libraries |
| `--list-entity-types` | List all available entity types |
| `--csv-relationships CSV_FILE` | Path to CSV file with relationships (recommended) |
| `--csv CSV_FILE` | Path to CSV file for legacy entity-only loading |
| `--library-id ID` | Target library ID (for legacy --csv mode) |
| `--entity-type TYPE` | Entity type name (for legacy --csv mode) |
| `--map "COL=FIELD"` | Column mapping in format "CSVColumn=APIField" (for legacy --csv mode) |
| `--dry-run` | Validate CSV without creating entities |

## CSV Validation

The validation feature checks for:

✅ **File Structure**
- UTF-8 encoding
- Valid CSV format
- Column headers present
- Data rows present

✅ **Required Columns**
- All required columns are present for relationship imports
- No duplicate column names
- No empty column headers

✅ **Data Quality**
- Empty rows and columns identification
- Empty values in required columns
- Overall file statistics

### Validation Output Example

```
================================================================================
CSV VALIDATION REPORT
================================================================================

Status: ✓ VALID

File Statistics:
  • Total columns: 18
  • Total rows: 9

Columns Present (18):
  • Library
  • Component
  • ComponentDescription
  • Threat
  • ThreatDescription
  • Category
  • Severity
  • STRIDE
  • Mitigation
  • SecurityRequirement
  • SecurityRequirementDescription
  • Priority
  • SecurityRequirementCategory
  • Standard
  • TestCase
  • TestCaseDescription
  • Property
  • PropertyValue

⚠ WARNINGS (1):
  1. Column 'Property' has 9/9 empty values

================================================================================

✓ CSV file is valid and ready for import!
```

## How It Works

### Entity Creation Flow

1. **Validation**: CSV structure is validated before processing
2. **Library Lookup**: Finds the target library by name
3. **Component Creation**: Creates or finds the component in the library
4. **Threat Creation**: Creates or finds the threat with metadata (severity, category, STRIDE)
5. **Security Requirement Creation**: Creates security requirements with priority and compliance standards
6. **Test Case Creation**: Creates test cases for validation
7. **Relationship Linking**: Links all entities together using unified relationship API
8. **Property Linking**: Links property options to threats (if specified)

### Entity Deduplication

The tool maintains a cache during each import session to avoid creating duplicate entities:
- Searches for existing entities by name before creating new ones
- Cache key format: `library_id:entity_type:name_lower`
- Reuses existing entity IDs when found

### Risk Level Mapping

Severity/Priority levels are automatically mapped to ThreatModeler risk levels:

| Severity/Priority | Risk ID | Risk Name |
|-------------------|---------|-----------|
| Critical, Very High | 1 | Very High |
| High | 2 | High |
| Medium | 3 | Medium |
| Low | 4 | Low |
| Very Low | 5 | Very Low |

## Sample Files

The repository includes several sample CSV files:

- `test_security_data.csv` - Full example with all columns and metadata
- `security_relationships.csv` - Basic example with minimal columns
- `sample_threats.csv` - Simple threat list
- `sample_security_requirements.csv` - Simple security requirements list

## Error Handling

The tool provides detailed error messages for common issues:

- **Missing Library**: Lists all available libraries if specified library not found
- **Invalid CSV**: Shows specific validation errors (encoding, structure, missing columns)
- **API Errors**: Displays HTTP status codes and error messages from ThreatModeler
- **Entity Creation Failures**: Logs which entities failed to create

## Best Practices

1. **Always validate first**: Use `--validate` before importing to catch issues early
2. **Use dry-run mode**: Test with `--dry-run` to preview operations
3. **Start small**: Begin with a few rows to test your CSV format
4. **Check libraries**: Verify target library exists with `--list-libraries`
5. **Consistent naming**: Use consistent entity names to leverage deduplication
6. **Include descriptions**: Provide meaningful descriptions for better documentation
7. **Add metadata**: Include severity, STRIDE, priorities, and standards for rich threat models
8. **Review logs**: Check console output for warnings and errors during import

## Troubleshooting

### CSV Validation Fails

**Issue**: Required columns are missing
- **Solution**: Ensure your CSV has all required columns: Library, Component, Threat, SecurityRequirement

**Issue**: File encoding error
- **Solution**: Save your CSV as UTF-8 encoded

### Import Fails

**Issue**: Library not found
- **Solution**: Run `--list-libraries` to get exact library names (case-sensitive)

**Issue**: Entity creation fails
- **Solution**: Check API credentials in `.env` file, verify library permissions

### Duplicates Created

**Issue**: Same entity created multiple times
- **Solution**: Ensure entity names match exactly (case-insensitive matching is used)

## API Endpoints Used

The tool interacts with the following ThreatModeler API endpoints:

- `GET /api/library/libraries` - List libraries
- `GET /api/library/entities` - List entity types
- `POST /api/library/getrecords` - Search for existing entities
- `POST /api/library/addrecords` - Create new entities
- `PUT /api/library/updaterecords` - Update entities (creation fallback)
- `POST /api/library/SaveComponentRelationshipDetails` - Create unified relationships
- `POST /api/library/SaveThreatSecurityRequirementsTestcases` - Link threats to SRs/test cases
- `POST /api/library/association` - Create entity associations

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

[Specify your license here]

## Support

For issues related to:
- **This tool**: Open an issue in this repository
- **ThreatModeler API**: Contact ThreatModeler support

## Version History

- **1.0.0** - Initial release with CSV validation, relationship management, and entity deduplication