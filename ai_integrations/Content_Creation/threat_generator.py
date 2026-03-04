"""
AI-Driven Threat and Security Requirements Generation

This module implements automated threat modeling using OpenAI's API to analyze
components, identify applicable CWEs, and generate security requirements.
"""

import os
import sys
import logging
import json
import time
import sqlite3
import argparse
import pandas as pd
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass, field
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI
from retry import retry

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Component:
    """Represents a system or hardware component for threat analysis."""
    name: str
    description: str
    type: Literal["hardware", "software"]
    technical_details: Dict[str, List[str]] = field(default_factory=dict)
    trust_boundaries: List[str] = field(default_factory=list)
    data_flows: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate component data after initialization."""
        if not self.name or not self.name.strip():
            raise ValueError("Component name cannot be empty")
        if not self.description or not self.description.strip():
            raise ValueError("Component description cannot be empty")
        if self.type not in ["hardware", "software"]:
            raise ValueError(f"Component type must be 'hardware' or 'software', got '{self.type}'")


class ComponentInputProcessor:
    """Handles validation and preparation of component information for analysis."""
    
    # Keywords for extracting technical details
    PROTOCOL_KEYWORDS = [
        'uart', 'i2c', 'spi', 'usb', 'tcp', 'udp', 'http', 'https', 'mqtt',
        'can', 'ethernet', 'wifi', 'bluetooth', 'modbus', 'zigbee', 'lora'
    ]
    
    INTERFACE_KEYWORDS = [
        'api', 'rest', 'graphql', 'interface', 'port', 'socket', 'endpoint',
        'serial', 'gpio', 'analog', 'digital', 'input', 'output'
    ]
    
    DATA_TYPE_KEYWORDS = [
        'sensor data', 'user data', 'credentials', 'authentication', 'password',
        'token', 'key', 'certificate', 'configuration', 'firmware', 'calibration',
        'measurement', 'temperature', 'pressure', 'voltage', 'current'
    ]
    
    TRUST_BOUNDARY_KEYWORDS = [
        'external', 'internal', 'network', 'internet', 'cloud', 'remote',
        'local', 'trusted', 'untrusted', 'public', 'private', 'boundary'
    ]
    
    @staticmethod
    def extract_technical_details(description: str) -> Dict[str, List[str]]:
        """
        Extract key technical details from component description.
        
        Args:
            description: Component description text
            
        Returns:
            Dictionary with categories: protocols, interfaces, data_types
        """
        description_lower = description.lower()
        
        protocols = [
            kw for kw in ComponentInputProcessor.PROTOCOL_KEYWORDS
            if kw in description_lower
        ]
        
        interfaces = [
            kw for kw in ComponentInputProcessor.INTERFACE_KEYWORDS
            if kw in description_lower
        ]
        
        data_types = [
            kw for kw in ComponentInputProcessor.DATA_TYPE_KEYWORDS
            if kw in description_lower
        ]
        
        return {
            'protocols': protocols,
            'interfaces': interfaces,
            'data_types': data_types
        }
    
    @staticmethod
    def identify_trust_boundaries(description: str) -> List[str]:
        """
        Identify potential trust boundaries from component description.
        
        Args:
            description: Component description text
            
        Returns:
            List of identified trust boundary indicators
        """
        description_lower = description.lower()
        
        boundaries = [
            kw for kw in ComponentInputProcessor.TRUST_BOUNDARY_KEYWORDS
            if kw in description_lower
        ]
        
        return boundaries
    
    @staticmethod
    def identify_data_flows(description: str, technical_details: Dict[str, List[str]]) -> List[str]:
        """
        Identify potential data flows from description and technical details.
        
        Args:
            description: Component description text
            technical_details: Extracted technical details
            
        Returns:
            List of identified data flow patterns
        """
        data_flows = []
        description_lower = description.lower()
        
        # Check for data flow indicators
        if 'send' in description_lower or 'transmit' in description_lower:
            data_flows.append('outbound_data_transmission')
        
        if 'receive' in description_lower or 'input' in description_lower:
            data_flows.append('inbound_data_reception')
        
        if 'store' in description_lower or 'persist' in description_lower:
            data_flows.append('data_storage')
        
        if 'process' in description_lower or 'compute' in description_lower:
            data_flows.append('data_processing')
        
        # Add protocol-specific flows
        for protocol in technical_details.get('protocols', []):
            data_flows.append(f'{protocol}_communication')
        
        return data_flows


def process_component_input(
    component_name: str,
    component_description: str,
    component_type: Literal["hardware", "software"]
) -> Component:
    """
    FR-1: Input Processing
    
    Validate and prepare component information for analysis.
    
    Args:
        component_name: Name of the component
        component_description: Detailed description of component functionality
        component_type: Type of component ("hardware" or "software")
        
    Returns:
        Validated Component object with extracted technical details
        
    Raises:
        ValueError: If validation fails
    """
    logger.info(f"Processing component input: {component_name} (type: {component_type})")
    
    # Validate inputs
    if not component_name or not component_name.strip():
        raise ValueError("Component name cannot be empty")
    
    if not component_description or not component_description.strip():
        raise ValueError("Component description cannot be empty")
    
    if component_type not in ["hardware", "software"]:
        raise ValueError(
            f"Component type must be 'hardware' or 'software', got '{component_type}'"
        )
    
    # Extract technical details
    technical_details = ComponentInputProcessor.extract_technical_details(
        component_description
    )
    
    # Identify trust boundaries
    trust_boundaries = ComponentInputProcessor.identify_trust_boundaries(
        component_description
    )
    
    # Identify data flows
    data_flows = ComponentInputProcessor.identify_data_flows(
        component_description,
        technical_details
    )
    
    # Create validated component object
    component = Component(
        name=component_name.strip(),
        description=component_description.strip(),
        type=component_type,
        technical_details=technical_details,
        trust_boundaries=trust_boundaries,
        data_flows=data_flows
    )
    
    logger.info(f"Component processed successfully: {component.name}")
    logger.debug(f"  Technical details: {component.technical_details}")
    logger.debug(f"  Trust boundaries: {component.trust_boundaries}")
    logger.debug(f"  Data flows: {component.data_flows}")
    
    return component


# ============================================================================
# FR-2: CWE Applicability Analysis
# ============================================================================

@dataclass
class CWEAnalysis:
    """Represents a CWE with relevance analysis for a component."""
    cwe_id: str
    name: str
    description: str
    relevance_score: int  # 1-10 scale
    relevance_level: Literal["High", "Medium", "Low"]
    justification: str
    attack_surface: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate CWE analysis data."""
        if not 1 <= self.relevance_score <= 10:
            raise ValueError(f"Relevance score must be between 1-10, got {self.relevance_score}")


class ThreatModelingAI:
    """Handles OpenAI API interactions for threat modeling."""
    
    def __init__(self):
        """Initialize OpenAI client with configuration from environment."""
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key or api_key == 'your_openai_api_key_here':
            raise ValueError(
                "OPENAI_API_KEY not set in .env file. "
                "Please set a valid OpenAI API key."
            )
        
        self.client = OpenAI(api_key=api_key)
        self.model = os.getenv('OPENAI_MODEL', 'gpt-4')
        self.temperature = float(os.getenv('OPENAI_TEMPERATURE', '0.3'))
        self.max_tokens = int(os.getenv('OPENAI_MAX_TOKENS', '4000'))
        self.max_retries = int(os.getenv('MAX_RETRIES', '3'))
        self.retry_delay = int(os.getenv('RETRY_DELAY', '2'))
        
        logger.info(f"Initialized ThreatModelingAI with model: {self.model}")
    
    @retry(tries=3, delay=2, backoff=2, logger=logger)
    def call_api(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: Optional[Dict] = None
    ) -> str:
        """
        Make API call with error handling and retry logic.
        
        Args:
            system_prompt: System message defining the AI's role
            user_prompt: User message with the task
            response_format: Optional JSON schema for structured output
            
        Returns:
            API response content as string
        """
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
            
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
                "max_tokens": self.max_tokens
            }
            
            # Add response_format for JSON mode if specified
            if response_format:
                kwargs["response_format"] = {"type": "json_object"}
            
            logger.debug(f"Calling OpenAI API with model: {self.model}")
            response = self.client.chat.completions.create(**kwargs)
            
            content = response.choices[0].message.content
            logger.info(f"API call successful. Tokens used: {response.usage.total_tokens}")
            
            return content
            
        except Exception as e:
            logger.error(f"API call failed: {e}")
            raise


def load_cwe_list(component_type: Literal["hardware", "software"]) -> pd.DataFrame:
    """
    Load appropriate CWE list based on component type.
    
    Args:
        component_type: Type of component ("hardware" or "software")
        
    Returns:
        DataFrame with CWE data including: CWE-ID, Name, Description, Status, etc.
        
    Raises:
        FileNotFoundError: If CWE list file doesn't exist
    """
    if component_type == "hardware":
        cwe_path = os.getenv('HARDWARE_CWE_LIST', './hardware_cwe_list.csv')
    else:
        cwe_path = os.getenv('SOFTWARE_CWE_LIST', './software_cwe_list.csv')
    
    if not os.path.exists(cwe_path):
        raise FileNotFoundError(f"CWE list not found: {cwe_path}")
    
    logger.info(f"Loading CWE list from: {cwe_path}")
    df = pd.read_csv(cwe_path)
    
    logger.info(f"Loaded {len(df)} CWEs for {component_type} components")
    return df


def analyze_applicable_cwes(
    component: Component,
    cwe_list: pd.DataFrame,
    ai_client: ThreatModelingAI,
    max_cwes: int = 15,
    batch_size: int = 25
) -> List[CWEAnalysis]:
    """
    FR-2: CWE Applicability Analysis
    
    Use OpenAI API to determine which CWEs apply to the component.
    
    Args:
        component: Processed component information
        cwe_list: DataFrame with CWE data
        ai_client: ThreatModelingAI instance for API calls
        max_cwes: Maximum number of CWEs to identify (default: 15)
        batch_size: Number of CWEs to analyze per API call (default: 25)
        
    Returns:
        List of CWEAnalysis objects sorted by relevance score (highest first)
    """
    logger.info(f"Analyzing applicable CWEs for component: {component.name}")
    
    all_applicable_cwes = []
    total_cwes = len(cwe_list)
    
    # Process CWEs in batches
    for batch_start in range(0, total_cwes, batch_size):
        batch_end = min(batch_start + batch_size, total_cwes)
        batch = cwe_list.iloc[batch_start:batch_end]
        
        logger.info(f"Processing CWE batch {batch_start+1}-{batch_end} of {total_cwes}")
        
        # Create CWE summary for this batch
        cwe_summary = []
        for _, cwe in batch.iterrows():
            # Handle potential NaN values by converting to string
            cwe_id = str(cwe['CWE-ID']) if pd.notna(cwe['CWE-ID']) else 'Unknown'
            name = str(cwe['Name']) if pd.notna(cwe['Name']) else 'Unknown'
            description = str(cwe['Description']) if pd.notna(cwe['Description']) else 'No description available'
            status = str(cwe.get('Status', 'Unknown')) if pd.notna(cwe.get('Status')) else 'Unknown'
            
            # Truncate description if too long
            if len(description) > 200:
                description = description[:200] + "..."
            
            cwe_summary.append(
                f"CWE-{cwe_id}: {name}\n"
                f"  Description: {description}\n"
                f"  Status: {status}"
            )
        
        # Build the prompt
        system_prompt = """You are a cybersecurity expert specializing in threat modeling and security weakness analysis. 
Your task is to analyze system components against Common Weakness Enumeration (CWE) patterns and determine applicability."""
        
        user_prompt = f"""Analyze this component against the provided CWEs and identify which ones are most applicable.

**Component Information:**
- Name: {component.name}
- Type: {component.type}
- Description: {component.description}

**Technical Context:**
- Protocols: {', '.join(component.technical_details.get('protocols', ['None detected']))}
- Interfaces: {', '.join(component.technical_details.get('interfaces', ['None detected']))}
- Data Types: {', '.join(component.technical_details.get('data_types', ['None detected']))}
- Trust Boundaries: {', '.join(component.trust_boundaries or ['None identified'])}
- Data Flows: {', '.join(component.data_flows or ['None identified'])}

**CWEs to Analyze:**
{chr(10).join(cwe_summary)}

**Analysis Instructions:**
For each CWE that is applicable to this component:
1. Assess relevance score (1-10 scale, where 10 = critically relevant)
2. Categorize as High (8-10), Medium (5-7), or Low (1-4) relevance
3. Explain WHY it applies specifically to this component
4. Consider the component's attack surface
5. Consider data flows and trust boundaries
6. Prioritize CWEs that are "Stable" or "Draft" status
7. Only include CWEs with relevance score >= 5

Return ONLY the applicable CWEs (relevance >= 5) in JSON format:
{{
  "applicable_cwes": [
    {{
      "cwe_id": "CWE-###",
      "name": "CWE Name",
      "relevance_score": 8,
      "relevance_level": "High",
      "justification": "Specific explanation of why this CWE applies to this component",
      "attack_surface": ["specific attack vector 1", "specific attack vector 2"]
    }}
  ]
}}"""
        
        try:
            # Call OpenAI API
            response = ai_client.call_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response)
            
            # Process applicable CWEs from this batch
            for cwe_data in result.get('applicable_cwes', []):
                # Get full CWE details from the dataframe
                cwe_id_num = cwe_data['cwe_id'].replace('CWE-', '')
                cwe_row = batch[batch['CWE-ID'].astype(str) == cwe_id_num]
                
                if not cwe_row.empty:
                    cwe_info = cwe_row.iloc[0]
                    
                    analysis = CWEAnalysis(
                        cwe_id=cwe_data['cwe_id'],
                        name=cwe_data['name'],
                        description=cwe_info['Description'],
                        relevance_score=cwe_data['relevance_score'],
                        relevance_level=cwe_data['relevance_level'],
                        justification=cwe_data['justification'],
                        attack_surface=cwe_data.get('attack_surface', [])
                    )
                    
                    all_applicable_cwes.append(analysis)
                    logger.info(
                        f"  ✓ {analysis.cwe_id} ({analysis.relevance_level}) - "
                        f"Score: {analysis.relevance_score}/10"
                    )
            
            # Small delay between batches to avoid rate limiting
            if batch_end < total_cwes:
                time.sleep(1)
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response as JSON: {e}")
            continue
        except Exception as e:
            logger.error(f"Error processing batch {batch_start}-{batch_end}: {e}")
            continue
    
    # Sort by relevance score (highest first) and limit to max_cwes
    all_applicable_cwes.sort(key=lambda x: x.relevance_score, reverse=True)
    top_cwes = all_applicable_cwes[:max_cwes]
    
    logger.info(
        f"\n✅ CWE Analysis Complete: {len(top_cwes)} most relevant CWEs identified "
        f"(from {len(all_applicable_cwes)} total applicable CWEs)"
    )
    
    return top_cwes


# ============================================================================
# FR-3: Threat Generation
# ============================================================================

@dataclass
class Threat:
    """Represents a security threat identified for a component."""
    threat_name: str
    threat_description: str
    category: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    stride: str  # STRIDE category
    mitigation: str
    cwe_ids: List[str] = field(default_factory=list)
    attack_prerequisites: List[str] = field(default_factory=list)
    potential_impact: str = ""
    
    def __post_init__(self):
        """Validate threat data."""
        if not self.threat_name or not self.threat_name.strip():
            raise ValueError("Threat name cannot be empty")
        if not self.threat_description or not self.threat_description.strip():
            raise ValueError("Threat description cannot be empty")
        if self.severity not in ["Critical", "High", "Medium", "Low"]:
            raise ValueError(f"Invalid severity: {self.severity}")


def generate_threats(
    component: Component,
    applicable_cwes: List[CWEAnalysis],
    ai_client: ThreatModelingAI,
    target_count: int = 10
) -> List[Threat]:
    """
    FR-3: Threat Generation
    
    Generate high-value security threats based on applicable CWEs.
    
    Args:
        component: Component information
        applicable_cwes: List of relevant CWEs from FR-2
        ai_client: ThreatModelingAI instance for API calls
        target_count: Target number of threats to generate (default: 10)
        
    Returns:
        List of Threat objects (prioritized by severity)
    """
    logger.info(f"Generating {target_count} threats for component: {component.name}")
    
    # Prepare CWE summary for prompt
    cwe_summary = []
    for cwe in applicable_cwes[:15]:  # Use top 15 CWEs for threat generation
        cwe_summary.append(
            f"- {cwe.cwe_id}: {cwe.name}\n"
            f"  Relevance: {cwe.relevance_level} ({cwe.relevance_score}/10)\n"
            f"  Why applicable: {cwe.justification[:150]}..."
        )
    
    # Build the prompt
    system_prompt = """You are a threat modeling expert with 15+ years of experience in secure system design. 
Your expertise includes STRIDE threat modeling, secure-by-design principles, and real-world attack scenarios. 
You identify high-value, actionable threats that help organizations build secure systems."""
    
    user_prompt = f"""Generate {target_count} high-value security threats for this component based on the applicable weaknesses.

**Component Information:**
- Name: {component.name}
- Type: {component.type}
- Description: {component.description}

**Technical Context:**
- Protocols: {', '.join(component.technical_details.get('protocols', ['None detected']))}
- Interfaces: {', '.join(component.technical_details.get('interfaces', ['None detected']))}
- Data Types Handled: {', '.join(component.technical_details.get('data_types', ['None detected']))}
- Trust Boundaries: {', '.join(component.trust_boundaries or ['None identified'])}
- Data Flows: {', '.join(component.data_flows or ['None identified'])}

**Applicable Security Weaknesses (CWEs):**
{chr(10).join(cwe_summary)}

**Threat Generation Requirements:**

1. **Quality over Quantity**: Focus on realistic, high-value threats that pose genuine risk
2. **Severity Distribution**: Aim for at least 7 Critical or High severity threats
3. **STRIDE Coverage**: Cover at least 4 different STRIDE categories:
   - Spoofing (impersonating another user/system)
   - Tampering (modifying data or code)
   - Repudiation (denying actions taken)
   - Information Disclosure (exposing information to unauthorized parties)
   - Denial of Service (degrading or preventing service)
   - Elevation of Privilege (gaining capabilities without authorization)

4. **Specificity**: Each threat must be specific to THIS component, not generic
5. **Actionability**: Include clear attack prerequisites and potential impacts
6. **Diversity**: Ensure variety in threat types (not all same attack vector)
7. **Secure-by-Design**: Consider threats that are best prevented through design

**For Each Threat, Provide:**
- threat_name: Clear, concise name (e.g., "Firmware Update Man-in-the-Middle Attack")
- threat_description: Detailed description of the attack scenario (2-3 sentences)
- category: Threat category (e.g., "Network Attack", "Physical Access", "Injection", "Authentication")
- severity: Critical, High, Medium, or Low (based on impact and likelihood)
- stride: Primary STRIDE category (one of: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- mitigation: High-level mitigation approach (1-2 sentences)
- cwe_ids: List of CWE IDs that relate to this threat (e.g., ["CWE-319", "CWE-494"])
- attack_prerequisites: List of what attacker needs (e.g., ["Network access", "Knowledge of protocol"])
- potential_impact: Specific impact if exploited (e.g., "Attacker gains root access to device")

Return EXACTLY {target_count} threats in JSON format:
{{
  "threats": [
    {{
      "threat_name": "Example Threat Name",
      "threat_description": "Detailed description...",
      "category": "Network Attack",
      "severity": "Critical",
      "stride": "Tampering",
      "mitigation": "Use encrypted channels...",
      "cwe_ids": ["CWE-319"],
      "attack_prerequisites": ["Network access"],
      "potential_impact": "Compromise device integrity"
    }}
  ]
}}"""
    
    try:
        # Call OpenAI API
        logger.info("Calling AI to generate threats...")
        response = ai_client.call_api(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format={"type": "json_object"}
        )
        
        # Parse response
        result = json.loads(response)
        
        # Process threats
        threats = []
        for threat_data in result.get('threats', []):
            threat = Threat(
                threat_name=threat_data['threat_name'],
                threat_description=threat_data['threat_description'],
                category=threat_data['category'],
                severity=threat_data['severity'],
                stride=threat_data['stride'],
                mitigation=threat_data['mitigation'],
                cwe_ids=threat_data.get('cwe_ids', []),
                attack_prerequisites=threat_data.get('attack_prerequisites', []),
                potential_impact=threat_data.get('potential_impact', '')
            )
            threats.append(threat)
            logger.info(
                f"  ✓ Generated: {threat.threat_name} "
                f"[{threat.severity}] [{threat.stride}]"
            )
        
        # Sort by severity (Critical > High > Medium > Low)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        threats.sort(key=lambda t: severity_order[t.severity])
        
        # Validate quality criteria
        high_severity_count = sum(
            1 for t in threats if t.severity in ["Critical", "High"]
        )
        unique_stride = len(set(t.stride for t in threats))
        
        logger.info(
            f"\n✅ Threat Generation Complete: {len(threats)} threats generated"
        )
        logger.info(f"   Critical/High Severity: {high_severity_count}/{len(threats)}")
        logger.info(f"   STRIDE Categories Covered: {unique_stride}")
        
        # Warning if quality criteria not met
        min_high_severity = int(os.getenv('MIN_HIGH_SEVERITY_THREATS', '7'))
        required_stride = int(os.getenv('REQUIRED_STRIDE_CATEGORIES', '4'))
        
        if high_severity_count < min_high_severity:
            logger.warning(
                f"⚠️  Only {high_severity_count} Critical/High threats "
                f"(target: ≥{min_high_severity})"
            )
        
        if unique_stride < required_stride:
            logger.warning(
                f"⚠️  Only {unique_stride} STRIDE categories "
                f"(target: ≥{required_stride})"
            )
        
        return threats
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse API response as JSON: {e}")
        raise
    except Exception as e:
        logger.error(f"Error generating threats: {e}")
        raise


# ============================================================================
# FR-4: Security Requirements Generation
# ============================================================================

@dataclass
class SecurityRequirement:
    """Represents a security requirement to mitigate a threat."""
    requirement_name: str
    requirement_description: str
    priority: Literal["Critical", "High", "Medium", "Low"]
    category: str  # e.g., Authentication, Input Validation, Data Protection
    standard: str  # e.g., OWASP ASVS 5.3.1, NIST 800-53 AC-2
    implementation_guidance: str = ""
    
    def __post_init__(self):
        """Validate security requirement data."""
        if not self.requirement_name or not self.requirement_name.strip():
            raise ValueError("Requirement name cannot be empty")
        if not self.requirement_description or not self.requirement_description.strip():
            raise ValueError("Requirement description cannot be empty")
        if self.priority not in ["Critical", "High", "Medium", "Low"]:
            raise ValueError(f"Invalid priority: {self.priority}")


def generate_security_requirements(
    threats: List[Threat],
    component: Component,
    ai_client: ThreatModelingAI
) -> List[SecurityRequirement]:
    """
    FR-4: Security Requirements Generation
    
    Create specific, testable security requirements for each threat.
    
    Args:
        threats: List of threats from FR-3
        component: Component information
        ai_client: ThreatModelingAI instance for API calls
        
    Returns:
        List of SecurityRequirement objects (one per threat)
    """
    logger.info(f"Generating security requirements for {len(threats)} threats")
    
    all_requirements = []
    
    for i, threat in enumerate(threats, 1):
        logger.info(f"Processing threat {i}/{len(threats)}: {threat.threat_name}")
        
        # Build the prompt
        system_prompt = """You are a security architect specializing in secure-by-design principles and security requirements engineering.
You create specific, measurable, testable security requirements that directly address identified threats while following industry best practices and standards."""
        
        user_prompt = f"""Create a comprehensive security requirement to mitigate this threat.

**Threat Information:**
- Threat: {threat.threat_name}
- Description: {threat.threat_description}
- Severity: {threat.severity}
- STRIDE Category: {threat.stride}
- Related CWEs: {', '.join(threat.cwe_ids)}
- Potential Impact: {threat.potential_impact}

**Component Context:**
- Component: {component.name}
- Type: {component.type}
- Description: {component.description}

**Requirement Generation Guidelines:**

1. **Direct Threat Mitigation**: The requirement must directly address and mitigate this specific threat
2. **Specificity**: Be specific to this component and threat, not generic security advice
3. **Measurable**: Include concrete criteria that can be verified
4. **Testable**: Can be validated through testing or inspection
5. **Secure-by-Design**: Emphasize prevention through design over detection/response
6. **Standards-Based**: Reference specific industry standards (OWASP ASVS, NIST 800-53, ISO 27001, PCI-DSS, IEC 62443, etc.)
7. **Actionable**: Provide clear implementation guidance

**Security Requirement Categories:**
- Authentication (identity verification)
- Authorization (access control)
- Input Validation (data sanitization)
- Output Encoding (preventing injection)
- Data Protection (encryption, confidentiality)
- Session Management (session security)
- Cryptography (key management, algorithms)
- Error Handling (secure error messages)
- Logging & Monitoring (audit trails)
- Network Security (secure communications)
- Physical Security (hardware protection)
- Supply Chain Security (component integrity)

**Priority Mapping:**
- Critical threat → Critical priority
- High threat → High priority
- Medium threat → Medium priority
- Low threat → Low priority

**Output Format:**
Provide ONE security requirement in JSON format:
{{
  "requirement_name": "Concise requirement name (e.g., 'Implement Encrypted Communication Channels')",
  "requirement_description": "Detailed description of what must be implemented. Must be specific, measurable, and testable. Include concrete acceptance criteria.",
  "priority": "{threat.severity}",
  "category": "Appropriate category from the list above",
  "standard": "Specific standard reference (e.g., 'OWASP ASVS 2.1.1' or 'NIST 800-53 SC-8')",
  "implementation_guidance": "Specific technical guidance on how to implement this requirement (2-3 sentences)"
}}"""
        
        try:
            # Call OpenAI API
            response = ai_client.call_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response)
            
            # Create SecurityRequirement object
            requirement = SecurityRequirement(
                requirement_name=result['requirement_name'],
                requirement_description=result['requirement_description'],
                priority=result['priority'],
                category=result['category'],
                standard=result['standard'],
                implementation_guidance=result.get('implementation_guidance', '')
            )
            
            all_requirements.append(requirement)
            logger.info(
                f"  ✓ Generated: {requirement.requirement_name} "
                f"[{requirement.priority}] [{requirement.category}]"
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response for threat '{threat.threat_name}': {e}")
            # Create a fallback requirement
            requirement = SecurityRequirement(
                requirement_name=f"Mitigate {threat.threat_name}",
                requirement_description=threat.mitigation,
                priority=threat.severity,
                category="General",
                standard="N/A",
                implementation_guidance="See threat mitigation details"
            )
            all_requirements.append(requirement)
            logger.warning(f"  ⚠️  Using fallback requirement for: {threat.threat_name}")
            
        except Exception as e:
            logger.error(f"Error generating requirement for threat '{threat.threat_name}': {e}")
            continue
    
    logger.info(
        f"\n✅ Security Requirements Generation Complete: "
        f"{len(all_requirements)} requirements generated"
    )
    
    return all_requirements


# ============================================================================
# FR-5: Test Case Generation
# ============================================================================

@dataclass
class TestCase:
    """Represents a test case to verify a security requirement."""
    test_case_name: str
    test_case_description: str
    expected_outcome: str = ""
    pass_fail_criteria: str = ""
    
    def __post_init__(self):
        """Validate test case data."""
        if not self.test_case_name or not self.test_case_name.strip():
            raise ValueError("Test case name cannot be empty")
        if not self.test_case_description or not self.test_case_description.strip():
            raise ValueError("Test case description cannot be empty")


def generate_test_cases(
    security_requirements: List[SecurityRequirement],
    threats: List[Threat],
    component: Component,
    ai_client: ThreatModelingAI
) -> List[TestCase]:
    """
    FR-5: Test Case Generation
    
    Create test cases to verify security requirements.
    
    Args:
        security_requirements: List of security requirements from FR-4
        threats: List of associated threats from FR-3
        component: Component information
        ai_client: ThreatModelingAI instance for API calls
        
    Returns:
        List of TestCase objects (one per requirement)
    """
    logger.info(f"Generating test cases for {len(security_requirements)} security requirements")
    
    all_test_cases = []
    
    for i, (requirement, threat) in enumerate(zip(security_requirements, threats), 1):
        logger.info(f"Processing requirement {i}/{len(security_requirements)}: {requirement.requirement_name}")
        
        # Build the prompt
        system_prompt = """You are a security testing expert specializing in verification and validation of security requirements.
You create specific, reproducible test cases that can verify whether security requirements are properly implemented."""
        
        user_prompt = f"""Create a specific test case to verify this security requirement.

**Security Requirement Information:**
- Requirement: {requirement.requirement_name}
- Description: {requirement.requirement_description}
- Priority: {requirement.priority}
- Category: {requirement.category}
- Standard: {requirement.standard}

**Associated Threat:**
- Threat: {threat.threat_name}
- Description: {threat.threat_description}
- Severity: {threat.severity}

**Component Context:**
- Component: {component.name}
- Type: {component.type}
- Description: {component.description}

**Test Case Generation Guidelines:**

1. **Verification Focus**: The test case must verify that the security requirement is properly implemented
2. **Specificity**: Be specific to this component and requirement, not generic test advice
3. **Reproducibility**: Anyone should be able to follow the test steps and get consistent results
4. **Measurability**: Include clear pass/fail criteria
5. **Completeness**: Include both what to test and what the expected outcome should be
6. **Automation Potential**: Consider if the test can be automated

**Test Case Types to Consider:**
- Positive Testing (verify correct behavior with valid inputs)
- Negative Testing (verify resilience against invalid/malicious inputs)
- Boundary Testing (test edge cases and limits)
- Authentication Testing (verify identity checks)
- Authorization Testing (verify access controls)
- Input Validation Testing (verify sanitization/validation)
- Encryption Testing (verify cryptographic protections)
- Error Handling Testing (verify secure error responses)

**Output Format:**
Provide ONE test case in JSON format:
{{
  "test_case_name": "Concise test case name (e.g., 'Verify Encrypted UART Communication')",
  "test_case_description": "Detailed test steps describing HOW to perform the test. Include: 1) Setup/preconditions, 2) Step-by-step test procedure, 3) What to observe/measure. Be specific and actionable.",
  "expected_outcome": "What should happen when the test is executed correctly (the passing scenario)",
  "pass_fail_criteria": "Specific criteria to determine if the test passes or fails. Include measurable/observable conditions."
}}"""
        
        try:
            # Call OpenAI API
            response = ai_client.call_api(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response)
            
            # Create TestCase object
            test_case = TestCase(
                test_case_name=result['test_case_name'],
                test_case_description=result['test_case_description'],
                expected_outcome=result.get('expected_outcome', ''),
                pass_fail_criteria=result.get('pass_fail_criteria', '')
            )
            
            all_test_cases.append(test_case)
            logger.info(
                f"  ✓ Generated: {test_case.test_case_name}"
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse API response for requirement '{requirement.requirement_name}': {e}")
            # Create a fallback test case
            test_case = TestCase(
                test_case_name=f"Verify {requirement.requirement_name}",
                test_case_description=f"Verify that {requirement.requirement_description}",
                expected_outcome="Requirement is properly implemented",
                pass_fail_criteria="Manual verification required"
            )
            all_test_cases.append(test_case)
            logger.warning(f"  ⚠️  Using fallback test case for: {requirement.requirement_name}")
            
        except Exception as e:
            logger.error(f"Error generating test case for requirement '{requirement.requirement_name}': {e}")
            continue
    
    logger.info(
        f"\n✅ Test Case Generation Complete: "
        f"{len(all_test_cases)} test cases generated"
    )
    
    return all_test_cases


# ============================================================================
# FR-6: Database Storage and Persistence
# ============================================================================

def init_database() -> str:
    """
    Initialize SQLite database with required schema.
    
    Returns:
        str: Path to the database file
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    logger.info(f"Initializing database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create components table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS components (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('hardware', 'software')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create threats table
    cursor.execute("""
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
            cwe_ids TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )
    """)
    
    # Create security_requirements table
    cursor.execute("""
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
        )
    """)
    
    # Create test_cases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requirement_id INTEGER NOT NULL,
            test_case_name TEXT NOT NULL,
            test_case_description TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (requirement_id) REFERENCES security_requirements(id)
        )
    """)
    
    # Create component_properties table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS component_properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id INTEGER NOT NULL,
            property_name TEXT NOT NULL,
            property_value TEXT,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )
    """)
    
    # Create cwe_analysis table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cwe_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id INTEGER NOT NULL,
            cwe_id TEXT NOT NULL,
            cwe_name TEXT,
            relevance_score INTEGER,
            justification TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (component_id) REFERENCES components(id)
        )
    """)
    
    conn.commit()
    conn.close()
    
    logger.info(f"✅ Database initialized successfully")
    return db_path


def save_component(component: Component) -> int:
    """
    Save component to database.
    
    Args:
        component: Component object to save
        
    Returns:
        int: ID of inserted component
    """
    db_path = os.getenv('DATABASE_PATH', './threat_model.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO components (name, description, type)
        VALUES (?, ?, ?)
        """,
        (component.name, component.description, component.type)
    )
    
    component_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    assert component_id is not None, "Failed to get component_id after INSERT"
    logger.info(f"✅ Component saved to database (ID: {component_id})")
    return component_id


def save_threat(component_id: int, threat: Threat) -> int:
    """
    Save threat to database.
    
    Args:
        component_id: ID of the component
        threat: Threat object to save
        
    Returns:
        int: ID of inserted threat
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
            'Security Engineering',
            threat.threat_name,
            threat.threat_description,
            threat.category,
            threat.severity,
            threat.stride,
            threat.mitigation,
            ','.join(threat.cwe_ids)
        )
    )
    
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    assert threat_id is not None, "Failed to get threat_id after INSERT"
    return threat_id


def save_security_requirement(threat_id: int, requirement: SecurityRequirement) -> int:
    """
    Save security requirement to database.
    
    Args:
        threat_id: ID of the associated threat
        requirement: SecurityRequirement object to save
        
    Returns:
        int: ID of inserted requirement
    """
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
            requirement.requirement_name,
            requirement.requirement_description,
            requirement.priority,
            requirement.category,
            requirement.standard
        )
    )
    
    requirement_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    assert requirement_id is not None, "Failed to get requirement_id after INSERT"
    return requirement_id


def save_test_case(requirement_id: int, test_case: TestCase) -> int:
    """
    Save test case to database.
    
    Args:
        requirement_id: ID of the associated security requirement
        test_case: TestCase object to save
        
    Returns:
        int: ID of inserted test case
    """
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
            test_case.test_case_name,
            test_case.test_case_description
        )
    )
    
    test_case_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    assert test_case_id is not None, "Failed to get test_case_id after INSERT"
    return test_case_id


def save_cwe_analysis(component_id: int, cwe: CWEAnalysis) -> int:
    """
    Save CWE analysis to database.
    
    Args:
        component_id: ID of the component
        cwe: CWEAnalysis object to save
        
    Returns:
        int: ID of inserted CWE analysis
    """
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
            cwe.cwe_id,
            cwe.name,
            cwe.relevance_score,
            cwe.justification
        )
    )
    
    cwe_analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    assert cwe_analysis_id is not None, "Failed to get cwe_analysis_id after INSERT"
    return cwe_analysis_id


def export_to_csv(component_id: int, output_path: str) -> pd.DataFrame:
    """
    Export component threat model to CSV format matching test_security_data.csv schema.
    
    This is the REQUIRED final output format - downstream scripts depend on this CSV.
    The CSV must exactly match the 18-column schema from test_security_data.csv.
    
    Args:
        component_id: ID of the component to export
        output_path: Path where CSV file will be saved
        
    Returns:
        pd.DataFrame: The exported data
    """
    logger.info(f"Exporting threat model to CSV: {output_path}")
    
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
    logger.info(f"✅ CSV export validated: {len(df)} rows, 18 columns")
    logger.info(f"📄 Output file: {output_path}")
    
    return df


# ============================================================================
# Main Workflow Function
# ============================================================================

def run_threat_modeling(
    component_name: str,
    component_description: str,
    component_type: Literal["hardware", "software"],
    output_dir: Optional[str] = None
) -> str:
    """
    Run complete threat modeling workflow for a component.
    
    Args:
        component_name: Name of the component to analyze
        component_description: Detailed description of the component
        component_type: Type of component ("hardware" or "software")
        output_dir: Optional custom output directory
        
    Returns:
        str: Path to the generated CSV file
    """
    print("=" * 80)
    print("AI-DRIVEN THREAT MODELING SYSTEM")
    print("=" * 80)
    print(f"\nComponent: {component_name}")
    print(f"Type: {component_type}")
    print("=" * 80)
    
    # Check API key
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key or api_key == 'your_openai_api_key_here':
        logger.error("❌ OPENAI_API_KEY not configured in .env file")
        print("\n⚠️  ERROR: OPENAI_API_KEY not configured")
        print("\nTo configure:")
        print("  1. Copy .env.example to .env")
        print("  2. Add your OpenAI API key to .env")
        sys.exit(1)
    
    # FR-1: Component Input Processing
    print("\n[FR-1] Processing Component Input...")
    component = process_component_input(component_name, component_description, component_type)
    print(f"✅ Component processed")
    print(f"   Protocols: {component.technical_details.get('protocols', [])}")
    print(f"   Data Types: {component.technical_details.get('data_types', [])}")
    
    # Initialize AI client
    ai_client = ThreatModelingAI()
    
    # FR-2: CWE Applicability Analysis
    print("\n[FR-2] Analyzing CWE Applicability...")
    cwe_list = load_cwe_list(component.type)
    print(f"   Loaded {len(cwe_list)} CWEs")
    
    applicable_cwes = analyze_applicable_cwes(
        component=component,
        cwe_list=cwe_list,
        ai_client=ai_client,
        max_cwes=int(os.getenv('MAX_CWE_ANALYSIS', '15')),
        batch_size=25
    )
    print(f"✅ {len(applicable_cwes)} applicable CWEs identified")
    
    # FR-3: Threat Generation
    print("\n[FR-3] Generating Threats...")
    threats = generate_threats(
        component=component,
        applicable_cwes=applicable_cwes,
        ai_client=ai_client,
        target_count=int(os.getenv('TARGET_THREAT_COUNT', '10'))
    )
    print(f"✅ {len(threats)} threats generated")
    
    # FR-4: Security Requirements Generation
    print("\n[FR-4] Generating Security Requirements...")
    security_requirements = generate_security_requirements(
        threats=threats,
        component=component,
        ai_client=ai_client
    )
    print(f"✅ {len(security_requirements)} security requirements generated")
    
    # FR-5: Test Case Generation
    print("\n[FR-5] Generating Test Cases...")
    test_cases = generate_test_cases(
        security_requirements=security_requirements,
        threats=threats,
        component=component,
        ai_client=ai_client
    )
    print(f"✅ {len(test_cases)} test cases generated")
    
    # FR-6: Database Storage and CSV Export
    print("\n[FR-6] Saving to Database and Exporting CSV...")
    
    # Initialize database
    db_path = init_database()
    
    # Save component
    component_id = save_component(component)
    
    # Save CWE analysis
    for cwe in applicable_cwes:
        save_cwe_analysis(component_id, cwe)
    
    # Save threats, requirements, and test cases
    for threat, requirement, test_case in zip(threats, security_requirements, test_cases):
        threat_id = save_threat(component_id, threat)
        requirement_id = save_security_requirement(threat_id, requirement)
        save_test_case(requirement_id, test_case)
    
    print(f"✅ Data saved to database: {db_path}")
    
    # Export to CSV
    if output_dir is None:
        output_dir = os.getenv('OUTPUT_DIRECTORY', './output/')
    os.makedirs(output_dir, exist_ok=True)
    
    output_filename = f"{component.name.replace(' ', '_')}_threat_model.csv"
    output_path = os.path.join(output_dir, output_filename)
    
    df = export_to_csv(component_id, output_path)
    
    # Summary
    print("\n" + "=" * 80)
    print("🎉 THREAT MODELING COMPLETE!")
    print("=" * 80)
    print(f"\n📊 Summary:")
    print(f"   • Component: {component.name}")
    print(f"   • CWEs Analyzed: {len(applicable_cwes)}")
    print(f"   • Threats: {len(threats)}")
    print(f"   • Security Requirements: {len(security_requirements)}")
    print(f"   • Test Cases: {len(test_cases)}")
    print(f"\n📁 Output Files:")
    print(f"   • Database: {db_path}")
    print(f"   • CSV: {output_path}")
    print(f"\n⚠️  CSV file is REQUIRED for downstream import scripts")
    print("=" * 80)
    
    return output_path


# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AI-Driven Threat Modeling System - Generate threats, requirements, and test cases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a hardware component
  python threat_generator.py \\
    --name "Temperature Sensor" \\
    --type hardware \\
    --description "IoT sensor with UART and I2C communication"
  
  # Analyze a software component
  python threat_generator.py \\
    --name "Authentication API" \\
    --type software \\
    --description "REST API handling user authentication with JWT tokens"
  
  # Run built-in test example
  python threat_generator.py --test
        """
    )
    
    parser.add_argument(
        '--name', '-n',
        type=str,
        help='Name of the component to analyze'
    )
    
    parser.add_argument(
        '--description', '-d',
        type=str,
        help='Detailed description of the component'
    )
    
    parser.add_argument(
        '--type', '-t',
        type=str,
        choices=['hardware', 'software'],
        help='Type of component (hardware or software)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Output directory for CSV file (default: ./output/)'
    )
    
    parser.add_argument(
        '--test',
        action='store_true',
        help='Run built-in test example (Industrial IoT Temperature Sensor)'
    )
    
    args = parser.parse_args()
    
    try:
        if args.test:
            # Run test example
            print("\n🧪 Running built-in test example...\n")
            output_path = run_threat_modeling(
                component_name="Industrial IoT Temperature Sensor",
                component_description="""
                An industrial IoT temperature sensor that measures temperature ranges 
                from -40°C to 125°C. It communicates via UART and I2C protocols,
                is powered by 3.3V supply, and contains firmware for calibration 
                and data processing. The sensor stores calibration data in EEPROM
                and can transmit readings to external systems over the network.
                """,
                component_type="hardware",
                output_dir=args.output
            )
        elif args.name and args.description and args.type:
            # Run with user-provided component
            output_path = run_threat_modeling(
                component_name=args.name,
                component_description=args.description,
                component_type=args.type,
                output_dir=args.output
            )
        else:
            parser.print_help()
            print("\n❌ Error: Either --test or all of --name, --description, and --type are required")
            sys.exit(1)
            
    except ValueError as e:
        logger.error(f"❌ Validation error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

