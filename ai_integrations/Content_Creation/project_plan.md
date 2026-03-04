# AI-Driven Threat and Security Requirements Generation

## Project Overview
This AI integration system automatically analyzes system or hardware components to identify applicable security weaknesses (CWEs), generate high-value threats, and produce corresponding security requirements using OpenAI's API.

## Goal
Generate **10 high-value secure-by-design threats** with comprehensive security requirements for any given component (system architecture or hardware).

## Critical Output Requirement
**⚠️ MANDATORY:** The system MUST export final results to a CSV file matching the exact schema of `test_security_data.csv` (18 columns). This CSV output is REQUIRED as it serves as the input for downstream processing and import scripts. While the system uses SQLite for internal data management, the CSV export is the essential deliverable.

---

## 1. System Architecture

### 1.1 High-Level Flow
```
Input: Component Description
    ↓
CWE Applicability Analysis (OpenAI)
    ↓
Threat Generation (OpenAI)
    ↓
Security Requirements Generation
    ↓
SQLite Database Storage
    ↓
CSV Export (REQUIRED OUTPUT)
    ↓
Output: CSV file matching test_security_data.csv schema
```

**Note:** The CSV output is MANDATORY - downstream scripts depend on this exact format for imports.

### 1.2 Core Components
1. **Input Handler** - Processes component descriptions
2. **CWE Analyzer** - Determines applicable CWEs using AI
3. **Threat Generator** - Creates security threats based on CWEs
4. **Requirements Generator** - Produces security requirements
5. **Database Manager** - Stores all data in SQLite with relational integrity
6. **CSV Exporter** - Exports to test_security_data.csv schema (REQUIRED for downstream imports)

---

## 2. Functional Requirements

### FR-1: Input Processing
**Function:** `process_component_input(component_name, component_description, component_type)`

**Purpose:** Validate and prepare component information for analysis

**Parameters:**
- `component_name` (string): Name of the component
- `component_description` (string): Detailed description of component functionality
- `component_type` (enum): "hardware" | "software"

**Returns:** Validated component object

**Requirements:**
- Must validate component description is not empty
- Must identify component type (hardware vs. software/system)
- Should extract key technical details (protocols, interfaces, data types)
- Should identify trust boundaries and data flows

### FR-2: CWE Applicability Analysis
**Function:** `analyze_applicable_cwes(component, cwe_list, max_cwes=15)`

**Purpose:** Use OpenAI API to determine which CWEs apply to the component

**Parameters:**
- `component` (object): Processed component information
- `cwe_list` (DataFrame): Loaded CWE list (hardware or software)
- `max_cwes` (int): Maximum number of CWEs to identify (default: 15)

**Returns:** List of applicable CWE objects with relevance scores

**AI Prompt Structure:**
```
You are a cybersecurity expert analyzing system components for security weaknesses.

Component: {component_name}
Type: {component_type}
Description: {component_description}

Analyze this component against the following CWEs and determine which ones are most applicable:
{cwe_list_summary}

For each applicable CWE:
1. Assess relevance (High/Medium/Low)
2. Explain why it applies to this component
3. Consider the component's attack surface
4. Consider data flows and trust boundaries

Return the top {max_cwes} most relevant CWEs in JSON format.
```

**Requirements:**
- Must use appropriate CWE list based on component type
- Must batch CWEs in groups (e.g., 20-30) for API efficiency
- Should score CWEs by relevance (1-10 scale)
- Should provide justification for each CWE selection
- Must handle API rate limiting and errors
- Should prioritize CWEs marked as "Stable" or "Draft" status

### FR-3: Threat Generation
**Function:** `generate_threats(component, applicable_cwes, target_count=10)`

**Purpose:** Generate high-value security threats based on applicable CWEs

**Parameters:**
- `component` (object): Component information
- `applicable_cwes` (list): List of relevant CWEs
- `target_count` (int): Target number of threats (default: 10)

**Returns:** List of threat objects

**AI Prompt Structure:**
```
As a threat modeling expert, generate security threats for this component.

Component: {component_name}
Description: {component_description}
Applicable Weaknesses: {cwe_summary}

Generate {target_count} high-value, actionable threats following secure-by-design principles:
1. Focus on realistic attack scenarios
2. Consider STRIDE categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
3. Prioritize threats by severity (Critical, High, Medium, Low)
4. Include specific attack vectors
5. Consider the component's operational context

For each threat, provide:
- Threat name
- Detailed description
- STRIDE category
- Severity level (Critical/High/Medium/Low)
- Related CWE-ID(s)
- Attack prerequisites
- Potential impact
```

**Requirements:**
- Must generate at least 10 threats
- Should prioritize Critical and High severity threats
- Must map each threat to STRIDE categories
- Must reference source CWE-IDs
- Should ensure threat diversity (not all same type)
- Should consider secure-by-design principles
- Must validate threat descriptions are specific to component

### FR-4: Security Requirements Generation
**Function:** `generate_security_requirements(threat, component, design_patterns)`

**Purpose:** Create specific, testable security requirements for each threat

**Parameters:**
- `threat` (object): Threat object from FR-3
- `component` (object): Component information
- `design_patterns` (dict): Secure design patterns library

**Returns:** SecurityRequirement object

**AI Prompt Structure:**
```
Create a comprehensive security requirement to mitigate this threat.

Threat: {threat_name}
Description: {threat_description}
Component: {component_name}
Severity: {severity}

Generate a security requirement that:
1. Directly addresses the threat
2. Is specific and measurable
3. Follows secure-by-design principles
4. References industry standards (OWASP ASVS, NIST, ISO 27001, etc.)
5. Includes implementation guidance

Provide:
- Requirement name
- Detailed requirement description
- Priority level (Critical/High/Medium/Low)
- Security requirement category (Authentication, Authorization, Input Validation, Data Protection, etc.)
- Relevant security standard(s)
- Suggested mitigation approaches
```

**Requirements:**
- Must create one requirement per threat
- Should reference industry standards (OWASP ASVS, NIST 800-53, PCI-DSS, etc.)
- Must assign priority based on threat severity
- Should categorize requirements appropriately
- Must ensure requirements are testable
- Should provide implementation guidance

### FR-5: Test Case Generation
**Function:** `generate_test_cases(security_requirement, threat)`

**Purpose:** Create test cases to verify security requirements

**Parameters:**
- `security_requirement` (object): Security requirement from FR-4
- `threat` (object): Associated threat

**Returns:** TestCase object

**AI Prompt Structure:**
```
Create a specific test case to verify this security requirement.

Security Requirement: {requirement_name}
Description: {requirement_description}  
Threat: {threat_name}

Generate a test case that:
1. Verifies the security requirement is properly implemented
2. Is reproducible and specific
3. Includes expected results
4. Can be automated if possible

Provide:
- Test case name
- Detailed test steps
- Expected outcome
- Pass/fail criteria
```

**Requirements:**
- Must generate at least one test case per requirement
- Should be specific and reproducible
- Must include pass/fail criteria
- Should consider both positive and negative test scenarios

### FR-6: Database Storage and Persistence
**Function:** `save_threat_model_to_database(component_id, threats, requirements, test_cases)`

**Purpose:** Store all generated threat model data in SQLite database with proper relationships

**Parameters:**
- `component_id` (int): Database ID of the component
- `threats` (list): Generated threats
- `requirements` (list): Security requirements
- `test_cases` (list): Test cases

**Returns:** Summary of saved records

**Database Storage Flow:**
```
1. For each threat:
   - Insert into 'threats' table
   - Link to component via component_id
   - Store CWE IDs as comma-separated string
   
2. For each security requirement:
   - Insert into 'security_requirements' table
   - Link to threat via threat_id
   
3. For each test case:
   - Insert into 'test_cases' table
   - Link to requirement via requirement_id

4. For each CWE analysis result:
   - Insert into 'cwe_analysis' table
   - Store relevance score and justification
```

**Database Schema Relationships:**
```
components (1) ----< (many) threats
threats (1) ----< (many) security_requirements
security_requirements (1) ----< (many) test_cases
components (1) ----< (many) component_properties
components (1) ----< (many) cwe_analysis
```

**Additional Database Helper Functions:**

**Function:** `save_security_requirement(threat_id, requirement_data)`
```python
def save_security_requirement(threat_id, requirement_data):
    """Save security requirement linked to a threat"""
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO security_requirements 
        (threat_id, requirement_name, requirement_description, 
         priority, category, standard)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            threat_id,
            requirement_data['requirement_name'],
            requirement_data['requirement_description'],
            requirement_data['priority'],
            requirement_data.get('category'),
            requirement_data.get('standard')
        )
    )
    
    requirement_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return requirement_id
```

**Function:** `save_test_case(requirement_id, test_case_data)`
```python
def save_test_case(requirement_id, test_case_data):
    """Save test case linked to a security requirement"""
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO test_cases 
        (requirement_id, test_case_name, test_case_description)
        VALUES (?, ?, ?)
        """,
        (
            requirement_id,
            test_case_data['test_case_name'],
            test_case_data['test_case_description']
        )
    )
    
    test_case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return test_case_id
```

**Function:** `save_cwe_analysis(component_id, cwe_id, analysis_data)`
```python
def save_cwe_analysis(component_id, cwe_id, analysis_data):
    """Save CWE analysis for a component"""
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO cwe_analysis 
        (component_id, cwe_id, cwe_name, relevance_score, justification)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            component_id,
            cwe_id,
            analysis_data.get('cwe_name'),
            analysis_data.get('relevance_score'),
            analysis_data.get('justification')
        )
    )
    
    conn.commit()
    conn.close()
```

**Requirements:**
- Must maintain referential integrity between tables
- Should use transactions for multi-record inserts
- Must handle database connection errors gracefully
- Should validate data before insertion
- Must provide atomic operations (all succeed or all fail)
- Should log all database operations for audit trail

---

## 3. Technical Implementation Details

### 3.1 OpenAI API Integration

**API Configuration:**
```python
import openai
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ThreatModelingAI:
    def __init__(self, model="gpt-4", max_tokens=4000):
        # Load API key from environment variable
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.model = model
        self.max_tokens = max_tokens
        openai.api_key = self.api_key
    
    def call_api(self, prompt, temperature=0.3, response_format="json"):
        """
        Make API call with error handling and retry logic
        """
        # Implementation with retry logic
        pass
```

**Environment Variables (.env file):**
```bash
# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_MAX_TOKENS=4000

# Database Configuration
DATABASE_PATH=./threat_model.db

# CWE List Paths
HARDWARE_CWE_LIST=./hardware_cwe_list.csv
SOFTWARE_CWE_LIST=./software_cwe_list.csv
```

**Requirements:**
- All secrets must be stored in .env file (never hardcoded)
- Use GPT-4 or GPT-4-turbo for best results
- Implement exponential backoff for rate limiting
- Use temperature ~0.3-0.5 for more consistent security analysis
- Log all API calls for audit trail
- Implement token usage tracking
- Cache responses where appropriate

### 3.2 SQLite Database Schema

**Database:** `threat_model.db`

**Table: components**
```sql
CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('hardware', 'software')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**Table: threats**
```sql
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    library TEXT DEFAULT 'Security Engineering',
    threat_name TEXT NOT NULL,
    threat_description TEXT NOT NULL,
    category TEXT,
    severity TEXT CHECK(severity IN ('Critical', 'High', 'Medium', 'Low')),
    stride TEXT,
    mitigation TEXT,
    cwe_ids TEXT,  -- Comma-separated CWE IDs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (component_id) REFERENCES components(id)
);
```

**Table: security_requirements**
```sql
CREATE TABLE IF NOT EXISTS security_requirements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id INTEGER NOT NULL,
    requirement_name TEXT NOT NULL,
    requirement_description TEXT NOT NULL,
    priority TEXT CHECK(priority IN ('Critical', 'High', 'Medium', 'Low')),
    category TEXT,
    standard TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(id)
);
```

**Table: test_cases**
```sql
CREATE TABLE IF NOT EXISTS test_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id INTEGER NOT NULL,
    test_case_name TEXT NOT NULL,
    test_case_description TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (requirement_id) REFERENCES security_requirements(id)
);
```

**Table: component_properties**
```sql
CREATE TABLE IF NOT EXISTS component_properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    property_name TEXT NOT NULL,
    property_value TEXT,
    FOREIGN KEY (component_id) REFERENCES components(id)
);
```

**Table: cwe_analysis**
```sql
CREATE TABLE IF NOT EXISTS cwe_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    component_id INTEGER NOT NULL,
    cwe_id TEXT NOT NULL,
    cwe_name TEXT,
    relevance_score INTEGER,
    justification TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (component_id) REFERENCES components(id)
);
```

### 3.3 Database Management Functions

**Function:** `init_database()`
```python
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

def init_database():
    """
    Initialize SQLite database with required schema
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create all tables (SQL from schema above)
    # ... execute CREATE TABLE statements
    
    conn.commit()
    conn.close()
    return db_path
```

**Function:** `save_component(name, description, component_type)`
```python
def save_component(name, description, component_type):
    """
    Save component to database
    
    Returns:
        component_id (int): ID of inserted component
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        "INSERT INTO components (name, description, type) VALUES (?, ?, ?)",
        (name, description, component_type)
    )
    
    component_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return component_id
```

**Function:** `save_threat(component_id, threat_data)`
```python
def save_threat(component_id, threat_data):
    """
    Save threat to database
    
    Returns:
        threat_id (int): ID of inserted threat
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO threats 
        (component_id, library, threat_name, threat_description, 
         category, severity, stride, mitigation, cwe_ids)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            component_id,
            threat_data.get('library', 'Security Engineering'),
            threat_data['threat_name'],
            threat_data['threat_description'],
            threat_data.get('category'),
            threat_data['severity'],
            threat_data['stride'],
            threat_data.get('mitigation'),
            ','.join(threat_data.get('cwe_ids', []))
        )
    )
    
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return threat_id
```

**Function:** `get_component_threats(component_id)`
```python
def get_component_threats(component_id):
    """
    Retrieve all threats for a component
    
    Returns:
        List of threat dictionaries
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM threats WHERE component_id = ?",
        (component_id,)
    )
    
    threats = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return threats
```

**Function:** `export_to_csv(component_id, output_path)` **[REQUIRED OUTPUT]**
```python
import pandas as pd

def export_to_csv(component_id, output_path):
    """
    Export component threat model to CSV format matching test_security_data.csv schema.
    
    This is the REQUIRED final output format - downstream scripts depend on this CSV.
    The CSV must exactly match the 18-column schema from test_security_data.csv.
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    
    query = """
    SELECT 
        t.library AS Library,
        c.name AS Component,
        c.description AS ComponentDescription,
        t.threat_name AS Threat,
        t.threat_description AS ThreatDescription,
        t.category AS Category,
        t.severity AS Severity,
        t.stride AS STRIDE,
        t.mitigation AS Mitigation,
        sr.requirement_name AS SecurityRequirement,
        sr.requirement_description AS SecurityRequirementDescription,
        sr.priority AS Priority,
        sr.category AS SecurityRequirementCategory,
        sr.standard AS Standard,
        tc.test_case_name AS TestCase,
        tc.test_case_description AS TestCaseDescription,
        cp.property_name AS Property,
        cp.property_value AS PropertyValue
    FROM threats t
    INNER JOIN components c ON t.component_id = c.id
    LEFT JOIN security_requirements sr ON t.id = sr.threat_id
    LEFT JOIN test_cases tc ON sr.id = tc.requirement_id
    LEFT JOIN component_properties cp ON c.id = cp.component_id
    WHERE c.id = ?
    """
    
    df = pd.read_sql_query(query, conn, params=(component_id,))
    conn.close()
    
    # Ensure all 18 columns from test_security_data.csv schema are present
    required_columns = [
        'Library', 'Component', 'ComponentDescription', 'Threat', 'ThreatDescription',
        'Category', 'Severity', 'STRIDE', 'Mitigation', 'SecurityRequirement',
        'SecurityRequirementDescription', 'Priority', 'SecurityRequirementCategory',
        'Standard', 'TestCase', 'TestCaseDescription', 'Property', 'PropertyValue'
    ]
    
    # Add missing columns with empty values if necessary
    for col in required_columns:
        if col not in df.columns:
            df[col] = ''
    
    # Reorder columns to match test_security_data.csv exactly
    df = df[required_columns]
    
    # Export to CSV (REQUIRED output format)
    df.to_csv(output_path, index=False)
    print(f"✅ CSV export validated: {len(df)} rows, 18 columns")
    
    return df
```

### 3.4 CWE List Processing

**Function:** `load_cwe_list(component_type)`
```python
import os
from dotenv import load_dotenv

load_dotenv()

def load_cwe_list(component_type):
    """
    Load appropriate CWE list based on component type
    
    Returns:
        DataFrame with columns: CWE-ID, Name, Description, etc.
    """
    if component_type == "hardware":
        cwe_path = os.getenv('HARDWARE_CWE_LIST', './hardware_cwe_list.csv')
    else:
        cwe_path = os.getenv('SOFTWARE_CWE_LIST', './software_cwe_list.csv')
    
    return pd.read_csv(cwe_path)
```

**Requirements:**
- Parse CSV files correctly
- Handle missing or malformed data
- Extract key fields: CWE-ID, Name, Description, Extended Description
- Create CWE summary for AI prompts (abbreviated descriptions)

### 3.3 Prompt Engineering Best Practices

**Key Principles:**
1. **Specificity**: Provide detailed context about the component
2. **Structure**: Use clear formatting and section headers
3. **Examples**: Include few-shot examples for consistent output format
4. **Constraints**: Explicitly state requirements and limitations
5. **Validation**: Request structured output (JSON) for easier parsing

**Example Structured Prompt:**
```
# Role
You are a cybersecurity threat modeling expert with 15+ years of experience in secure system design.

# Task
Analyze the following component and identify applicable security weaknesses.

# Component Information
Name: {name}
Type: {type}
Description: {description}

# Analysis Criteria
- Consider the component's attack surface
- Evaluate data flows and trust boundaries
- Assess potential vulnerabilities based on the component's function
- Prioritize weaknesses with realistic attack scenarios

# Output Format
Provide your analysis in JSON format:
{
  "applicable_cwes": [
    {
      "cwe_id": "CWE-XXX",
      "relevance_score": 8,
      "justification": "..."
    }
  ]
}
```

### 3.4 Data Validation

**Validation Requirements:**
- Verify CWE-IDs exist in loaded CWE list
- Ensure STRIDE categories are valid
- Validate severity levels
- Check for required fields in output
- Verify threat-requirement-testcase relationships
- Ensure output meets schema requirements

### 3.5 Error Handling

**Error Scenarios:**
1. **API Errors**: Rate limits, timeouts, invalid responses
2. **Data Errors**: Missing CWE data, malformed CSV
3. **Validation Errors**: Invalid output format from AI
4. **Business Logic Errors**: Not enough threats generated

**Handling Strategy:**
- Implement retry logic with exponential backoff
- Provide fallback options for partial failures
- Log all errors with context
- Return partial results when possible
- Provide clear error messages to users

---

## 4. Implementation Workflow

### Phase 1: Input and Initialization
```python
from dotenv import load_dotenv
import os

def main(component_name, component_description, component_type):
    # 0. Load environment variables
    load_dotenv()
    
    # 1. Initialize database
    db_path = init_database()
    print(f"Database initialized at: {db_path}")
    
    # 2. Initialize AI client (loads API key from .env)
    ai_client = ThreatModelingAI()
    
    # 3. Save component to database
    component_id = save_component(
        component_name,
        component_description,
        component_type
    )
    print(f"Component saved with ID: {component_id}")
    
    # 4. Process input
    component = {
        'id': component_id,
        'name': component_name,
        'description': component_description,
        'type': component_type
    }
    
    # 5. Load appropriate CWE list
    cwe_list = load_cwe_list(component_type)
```

### Phase 2: CWE Analysis
```python
    # 4. Analyze applicable CWEs
    applicable_cwes = analyze_applicable_cwes(
        component=component,
        cwe_list=cwe_list,
        ai_client=ai_client,
        max_cwes=15
    )
    
    # 5. Rank and filter CWEs
    top_cwes = rank_cwes_by_relevance(applicable_cwes, top_n=10)
```

### Phase 3: Threat and Requirements Generation
```python
    # 6. Generate threats
    threats = generate_threats(
        component=component,
        applicable_cwes=top_cwes,
        ai_client=ai_client,
        target_count=10
    )
    
    # 7. Generate security requirements
    requirements = []
    for threat in threats:
        req = generate_security_requirements(
            threat=threat,
            component=component,
            ai_client=ai_client
        )
        requirements.append(req)
    
    # 8. Generate test cases
    test_cases = []
    for req in requirements:
        tc = generate_test_cases(
            security_requirement=req,
            threat=req.related_threat,
            ai_client=ai_client
        )
        test_cases.append(tc)
```

### Phase 4: Database Storage and Output
```python
    # 9. Save all data to database
    for i, threat in enumerate(threats):
        # Save threat
        threat_id = save_threat(component_id, threat)
        
        # Save security requirement
        req_id = save_security_requirement(threat_id, requirements[i])
        
        # Save test case
        tc_id = save_test_case(req_id, test_cases[i])
        
        # Save CWE analysis
        if threat.get('cwe_ids'):
            for cwe_id in threat['cwe_ids']:
                save_cwe_analysis(component_id, cwe_id, threat)
    
    print(f"✅ Saved {len(threats)} threats to database")
    
    # 10. Export to CSV (REQUIRED - downstream scripts depend on this)
    output_path = f"./output/{component['name']}_threats.csv"
    output_df = export_to_csv(component_id, output_path)
    print(f"📄 CSV export complete: {output_path}")
    print(f"⚠️  CSV file is REQUIRED for import into downstream processing scripts")
    
    # 11. Return summary
    return {
        'component_id': component_id,
        'threats_generated': len(threats),
        'database_path': os.getenv('DATABASE_PATH'),
        'export_path': output_path,
        'dataframe': output_df
    }
```

---

## 5. Quality Criteria

### 5.1 Threat Quality Metrics
- **Specificity**: Threats must be specific to the component, not generic
- **Actionability**: Each threat should have clear mitigations
- **Severity Alignment**: Severity must match impact and likelihood
- **Diversity**: Threats should cover multiple STRIDE categories
- **Realism**: Attack scenarios should be feasible

### 5.2 Requirement Quality Metrics
- **Testability**: Requirements must be verifiable through testing
- **Clarity**: Requirements should be unambiguous
- **Completeness**: Requirements must fully address the threat
- **Standards Alignment**: Should reference recognized standards
- **Implementation Guidance**: Should include practical guidance

### 5.3 Output Quality Validation
```python
def validate_output_quality(threats, requirements, test_cases):
    """
    Validate generated output meets quality criteria
    """
    checks = {
        'threat_count': len(threats) >= 10,
        'high_severity_threats': sum(t.severity in ['Critical', 'High'] for t in threats) >= 7,
        'stride_coverage': len(set(t.stride for t in threats)) >= 4,
        'requirements_complete': len(requirements) == len(threats),
        'test_cases_complete': len(test_cases) == len(requirements),
        'standards_referenced': all(r.standard for r in requirements)
    }
    return all(checks.values()), checks
```

---

## 6. Configuration and Parameters

### 6.1 Environment Configuration (.env)

**All configuration should be loaded from .env file:**

```bash
# .env file structure

# OpenAI API Configuration
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.3
OPENAI_MAX_TOKENS=4000

# Database Configuration
DATABASE_PATH=./threat_model.db

# CWE Data Paths
HARDWARE_CWE_LIST=./hardware_cwe_list.csv
SOFTWARE_CWE_LIST=./software_cwe_list.csv

# Output Configuration
OUTPUT_DIRECTORY=./output/

# Threat Generation Parameters
TARGET_THREAT_COUNT=10
MAX_CWE_ANALYSIS=15
MIN_HIGH_SEVERITY_THREATS=7

# Quality Thresholds
MIN_RELEVANCE_SCORE=6
REQUIRED_STRIDE_CATEGORIES=4

# API Management
MAX_RETRIES=3
RETRY_DELAY=2
RATE_LIMIT_PAUSE=60
```

### 6.2 Configuration Loading
```python
import os
from dotenv import load_dotenv

def load_config():
    """
    Load configuration from .env file
    
    Returns:
        dict: Configuration dictionary
    """
    load_dotenv()
    
    return {
        # AI Configuration
        'openai_model': os.getenv('OPENAI_MODEL', 'gpt-4'),
        'temperature': float(os.getenv('OPENAI_TEMPERATURE', '0.3')),
        'max_tokens': int(os.getenv('OPENAI_MAX_TOKENS', '4000')),
        
        # Database
        'database_path': os.getenv('DATABASE_PATH', './threat_model.db'),
        
        # Threat Generation
        'target_threat_count': int(os.getenv('TARGET_THREAT_COUNT', '10')),
        'max_cwe_analysis': int(os.getenv('MAX_CWE_ANALYSIS', '15')),
        'min_high_severity_threats': int(os.getenv('MIN_HIGH_SEVERITY_THREATS', '7')),
        
        # Quality Thresholds
        'min_relevance_score': int(os.getenv('MIN_RELEVANCE_SCORE', '6')),
        'required_stride_categories': int(os.getenv('REQUIRED_STRIDE_CATEGORIES', '4')),
        
        # API Management
        'max_retries': int(os.getenv('MAX_RETRIES', '3')),
        'retry_delay': int(os.getenv('RETRY_DELAY', '2')),
        'rate_limit_pause': int(os.getenv('RATE_LIMIT_PAUSE', '60')),
        
        # Paths
        'hardware_cwe_list': os.getenv('HARDWARE_CWE_LIST', './hardware_cwe_list.csv'),
        'software_cwe_list': os.getenv('SOFTWARE_CWE_LIST', './software_cwe_list.csv'),
        'output_directory': os.getenv('OUTPUT_DIRECTORY', './output/')
    }

# Usage
config = load_config()
```

### 6.3 Security Best Practices

**IMPORTANT:**
- ❌ Never commit `.env` file to version control
- ✅ Add `.env` to `.gitignore`
- ✅ Provide `.env.example` template for team members
- ✅ Use environment-specific .env files (.env.dev, .env.prod)
- ✅ Validate all required environment variables on startup
- ✅ Use strong, unique API keys for each environment

**.env.example template:**
```bash
# Copy this file to .env and fill in your actual values

# OpenAI API Configuration
OPENAI_API_KEY=your_api_key_here
OPENAI_MODEL=gpt-4
OPENAI_TEMPERATURE=0.3
OPENAI_MAX_TOKENS=4000

# Database Configuration
DATABASE_PATH=./threat_model.db

# CWE Data Paths
HARDWARE_CWE_LIST=./hardware_cwe_list.csv
SOFTWARE_CWE_LIST=./software_cwe_list.csv

# Output Configuration
OUTPUT_DIRECTORY=./output/
```

**.gitignore additions:**
```
# Environment variables
.env
.env.local
.env.*.local

# Database
*.db
*.sqlite
*.sqlite3

# API keys and secrets
*_key.txt
*_secret.txt
```

---

## 7. Example Usage

### 7.1 Hardware Component Example
```python
result = main(
    component_name="Industrial IoT Temperature Sensor",
    component_description="""
    An industrial IoT temperature sensor that:
    - Measures temperature ranges from -40°C to 125°C
    - Communicates via UART and I2C protocols
    - Powered by 3.3V supply
    - Contains firmware for calibration and data processing
    - Stores calibration data in EEPROM
    - Sends data to a master controller every 5 seconds
    """,
    component_type="hardware"
)
```

### 7.2 Software Component Example
```python
result = main(
    component_name="User Authentication API",
    component_description="""
    RESTful API service that:
    - Handles user login and registration
    - Supports OAuth 2.0 and JWT tokens
    - Stores user credentials in PostgreSQL database
    - Implements rate limiting on authentication endpoints
    - Logs authentication attempts
    - Supports multi-factor authentication (MFA)
    """,
    component_type="software"
)
```

---

## 8. Success Criteria

The system successfully completes when:
1. ✅ 10 distinct, high-value threats are generated
2. ✅ At least 7 threats are rated High or Critical severity
3. ✅ Threats cover at least 4 different STRIDE categories
4. ✅ Each threat has a corresponding security requirement
5. ✅ Each requirement references at least one security standard
6. ✅ Each requirement has at least one test case
7. ✅ All output data conforms to test_security_data.csv schema (18 columns)
8. ✅ All CWE references are valid and from the appropriate list
9. ✅ CSV file is successfully exported and ready for downstream import scripts

---

## 9. Future Enhancements

### 9.1 Automated Risk Scoring
- Implement DREAD or CVSS-based risk scoring
- Consider business context and asset criticality
- Prioritize threats based on quantitative risk

### 9.2 Attack Tree Generation
- Generate attack trees showing threat progression
- Identify attack paths and defensive layers
- Visualize threat relationships

### 9.3 Mitigation Cost Analysis
- Estimate implementation effort for each requirement
- Suggest cost-effective alternatives
- Prioritize quick wins

### 9.4 Interactive Refinement
- Allow users to provide feedback on generated threats
- Iteratively refine threats based on context
- Build organizational threat library

### 9.5 Threat Intelligence Integration
- Incorporate CVE and exploit databases
- Reference real-world attack patterns
- Keep current with emerging threats

---

## 10. Dependencies

### Required Libraries
```txt
openai>=1.0.0
pandas>=2.0.0
python-dotenv>=1.0.0
retry>=0.9.2
jsonschema>=4.0.0
```

**Note:** SQLite3 is included in Python standard library (no separate installation needed)

### Required Files
- `hardware_cwe_list.csv` - CWE list for hardware components
- `software_cwe_list.csv` - CWE list for software components
- `.env` - Environment variables and secrets (create from .env.example)
- `.env.example` - Template for environment configuration

### Database Files (Created Automatically)
- `threat_model.db` - SQLite database (auto-created on first run)

### Required Environment Variables (in .env)
- `OPENAI_API_KEY` - OpenAI API key (required)
- `DATABASE_PATH` - Path to SQLite database (default: ./threat_model.db)
- `HARDWARE_CWE_LIST` - Path to hardware CWE list CSV
- `SOFTWARE_CWE_LIST` - Path to software CWE list CSV
- See Configuration section for complete list

---

## 11. Deliverables

### Primary Output
1. **CSV Threat Model File** (`{component_name}_threats.csv`) **[REQUIRED]**
   - **Format:** Must exactly match test_security_data.csv schema (18 columns)
   - **Purpose:** Primary output consumed by downstream import scripts
   - **Columns:** Library, Component, ComponentDescription, Threat, ThreatDescription, Category, Severity, STRIDE, Mitigation, SecurityRequirement, SecurityRequirementDescription, Priority, SecurityRequirementCategory, Standard, TestCase, TestCaseDescription, Property, PropertyValue
   - **Note:** This CSV file is MANDATORY - all downstream processing depends on this exact format

### Implementation Files
2. **Python Implementation** (`threat_generator.py`)
   - All core functions implemented
   - Error handling and logging
   - Configuration management from .env
   - SQLite database integration
   
3. **Database Management** (`database.py`)
   - Schema initialization
   - CRUD operations for all entities
   - Query functions for retrieving data
   - CSV export functionality matching test_security_data.csv
   
4. **Configuration Files**
   - `.env.example` - Template for configuration
   - `.gitignore` - Ensure secrets are not committed

### Supporting Artifacts
5. **SQLite Database** (`threat_model.db`)
   - Stores all threat modeling data
   - Enables querying and analysis
   - Serves as source for required CSV export
   
6. **Documentation**
   - API documentation
   - Usage examples
   - Configuration guide
   - Database schema documentation
   
5. **Test Suite**
   - Unit tests for core functions
   - Database integration tests
   - Integration tests with mock API
   - Test data samples
   
6. **Output Examples**
   - Example SQLite databases with sample data
   - Exported CSV files for compatibility
   - Query examples for common use cases

---

## Document Control

**Version:** 1.0  
**Last Updated:** 2026-03-04  
**Status:** Draft  
**Owner:** Security Engineering Team
