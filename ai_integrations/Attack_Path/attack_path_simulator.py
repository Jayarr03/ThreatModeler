#!/usr/bin/env python3
"""
Attack Path Simulator
=====================
This script generates high-likelihood attack paths by integrating:
- MITRE ATT&CK framework data
- ThreatModeler threat intelligence
- OpenAI's language models for attack path generation

Author: ThreatModeler Team
Version: 1.0.0
Date: March 10, 2026
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import pickle
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

import requests
from dotenv import load_dotenv
import pandas as pd
from openai import OpenAI
import colorlog


# ============================================================================
# Configuration and Logging Setup
# ============================================================================

class Config:
    """Application configuration loaded from environment variables."""
    
    def __init__(self, env_file: Optional[str] = None):
        """Initialize configuration from .env file or environment."""
        if env_file:
            load_dotenv(env_file)
        else:
            load_dotenv()
        
        # ThreatModeler Configuration
        self.threatmodeler_api_url = os.getenv('THREATMODELER_API_URL', '')
        self.threatmodeler_api_key = os.getenv('THREATMODELER_API_KEY', '')
        
        # OpenAI Configuration
        self.openai_api_key = os.getenv('OPENAI_API_KEY', '')
        self.openai_model = os.getenv('OPENAI_MODEL', 'gpt-4')
        self.openai_max_tokens = int(os.getenv('OPENAI_MAX_TOKENS', '2000'))
        self.openai_temperature = float(os.getenv('OPENAI_TEMPERATURE', '0.7'))
        
        # MITRE ATT&CK Configuration
        self.mitre_stix_url = os.getenv(
            'MITRE_STIX_URL',
            'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        )
        self.mitre_cache_dir = Path(os.getenv('MITRE_CACHE_DIR', './cache/mitre'))
        self.mitre_cache_expiry_days = int(os.getenv('MITRE_CACHE_EXPIRY_DAYS', '7'))
        
        # Application Configuration
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.output_dir = Path(os.getenv('OUTPUT_DIR', './output'))
        self.max_attack_paths_per_threat = int(os.getenv('MAX_ATTACK_PATHS_PER_THREAT', '3'))
        self.min_likelihood_score = int(os.getenv('MIN_LIKELIHOOD_SCORE', '5'))
        
        # Parallel Processing Configuration
        self.max_workers = int(os.getenv('MAX_WORKERS', '8'))  # Number of concurrent OpenAI API calls
        self.max_threats_to_process = int(os.getenv('MAX_THREATS_TO_PROCESS', '0'))  # 0 = process all threats
    
    def validate(self) -> bool:
        """Validate that required configuration is present."""
        errors = []
        
        if not self.threatmodeler_api_url:
            errors.append("THREATMODELER_API_URL is required")
        if not self.threatmodeler_api_key:
            errors.append("THREATMODELER_API_KEY is required")
        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required")
        
        if errors:
            for error in errors:
                logging.error(error)
            return False
        
        return True


def setup_logging(log_level: str = 'INFO'):
    """Set up colored logging for the application."""
    
    # Create color formatter
    formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    
    # Set up console handler
    handler = colorlog.StreamHandler()
    handler.setFormatter(formatter)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.addHandler(handler)
    
    return logger


# ============================================================================
# ThreatModeler API Client
# ============================================================================

class ThreatModelerClient:
    """Client for interacting with ThreatModeler API."""
    
    def __init__(self, api_url: str, api_key: str):
        """Initialize ThreatModeler API client.
        
        Args:
            api_url: Base URL for ThreatModeler API
            api_key: API key for authentication
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-ThreatModeler-ApiKey': api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        self.logger = logging.getLogger(__name__)
    
    def test_connection(self) -> bool:
        """Test the connection to ThreatModeler API.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self.session.get(f"{self.api_url}/api/groups", timeout=10)
            response.raise_for_status()
            self.logger.info("Successfully connected to ThreatModeler API")
            return True
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to connect to ThreatModeler API: {e}")
            return False
    
    def get_project(self, project_guid: str) -> Optional[Dict[str, Any]]:
        """Retrieve project/diagram details by GUID.
        
        Args:
            project_guid: The unique identifier for the threat model
            
        Returns:
            Diagram data as dictionary containing project info, components, and threats
        """
        try:
            self.logger.info(f"Fetching diagram for project: {project_guid}")
            response = self.session.get(
                f"{self.api_url}/api/diagram/{project_guid}",
                timeout=30
            )
            
            # Log response details for debugging
            self.logger.debug(f"Response status: {response.status_code}")
            self.logger.debug(f"Response headers: {response.headers}")
            
            response.raise_for_status()
            
            # Check if response has content
            if not response.text:
                self.logger.error("Empty response from API")
                return None
            
            try:
                return response.json()
            except ValueError as json_err:
                self.logger.error(f"Invalid JSON response: {json_err}")
                self.logger.debug(f"Response text: {response.text[:500]}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to retrieve project {project_guid}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.debug(f"Error response text: {e.response.text[:500]}")
            return None
    
    def get_project_threats(self, project_guid: str) -> List[Dict[str, Any]]:
        """Retrieve all threats for a project.
        
        Args:
            project_guid: The unique identifier for the project
            
        Returns:
            List of threat dictionaries extracted from the report API
        """
        try:
            self.logger.info(f"Fetching threats for project: {project_guid}")
            
            # Use the Report API to get threats with security requirements
            response = self.session.post(
                f"{self.api_url}/api/Report/project/getthreatswithsecurityrequirements",
                json={
                    "guid": project_guid,
                    "includeThreatsOrSR": True
                },
                timeout=30
            )
            
            self.logger.debug(f"Response status: {response.status_code}")
            response.raise_for_status()
            
            if not response.text:
                self.logger.warning("Empty response from threats API")
                return []
            
            try:
                data = response.json()
                self.logger.debug(f"Response keys: {data.keys() if isinstance(data, dict) else 'Not a dict'}")
                
                # Extract threats from response
                threats = []
                
                if isinstance(data, dict):
                    # Check for wrapped response (case-insensitive)
                    if 'Data' in data:
                        actual_data = data.get('Data', [])
                    elif 'data' in data:
                        actual_data = data.get('data', [])
                    else:
                        actual_data = data
                    
                    self.logger.debug(f"Actual data type: {type(actual_data)}, is list: {isinstance(actual_data, list)}")
                    if isinstance(actual_data, list):
                        self.logger.debug(f"Data is list with {len(actual_data)} items")
                    elif isinstance(actual_data, dict):
                        self.logger.debug(f"Data is dict with keys: {list(actual_data.keys())[:10]}")
                    
                    # The response might be a list of threats or contain a threats field
                    if isinstance(actual_data, list):
                        threats = actual_data
                    elif isinstance(actual_data, dict) and 'threats' in actual_data:
                        threats = actual_data.get('threats', [])
                    elif isinstance(actual_data, dict) and 'Threats' in actual_data:
                        threats = actual_data.get('Threats', [])
                
                self.logger.info(f"Retrieved {len(threats)} threats from Report API")
                
                if threats and len(threats) > 0:
                    self.logger.debug(f"Sample threat structure: {threats[0]}")
                
                return threats
                
            except ValueError as json_err:
                self.logger.error(f"Invalid JSON response: {json_err}")
                return []
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to retrieve threats: {e}")
            if hasattr(e, 'response') and e.response is not None:
                self.logger.debug(f"Error response text: {e.response.text[:500]}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return []
    
    def get_project_components(self, project_guid: str) -> List[Dict[str, Any]]:
        """Retrieve all components for a project.
        
        Args:
            project_guid: The unique identifier for the project
            
        Returns:
            List of component dictionaries extracted from diagram data
        """
        try:
            self.logger.info(f"Fetching components for project: {project_guid}")
            diagram_data = self.get_project(project_guid)
            
            if not diagram_data:
                return []
            
            # Extract components from diagram data
            components = []
            
            if isinstance(diagram_data, dict):
                # Check if response is wrapped (has 'Data' key)
                if 'Data' in diagram_data:
                    actual_data = diagram_data.get('Data', {})
                else:
                    actual_data = diagram_data
                
                # The diagram model might be nested in a 'Model' field
                if isinstance(actual_data, dict) and 'Model' in actual_data:
                    model_data = actual_data.get('Model', {})
                else:
                    model_data = actual_data
                
                # Try different possible locations
                node_data = model_data.get('nodeDataArray', []) or model_data.get('components', []) if isinstance(model_data, dict) else []
                
                if isinstance(node_data, list):
                    # Filter for component nodes (not threats)
                    components = [
                        item for item in node_data
                        if isinstance(item, dict) and
                        item.get('category', '').lower() != 'threat' and
                        item.get('Category', '').lower() != 'threat'
                    ]
            
            self.logger.info(f"Retrieved {len(components)} components")
            return components
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve components: {e}")
            return []
    
    def list_projects(self) -> List[Dict[str, Any]]:
        """Retrieve all active projects accessible to the user.
        
        Returns:
            List of project dictionaries with basic info
        """
        try:
            self.logger.info("Fetching all active projects")
            # Use the integration endpoint for listing projects
            response = self.session.get(
                f"{self.api_url}/api/integration/pipeline/activeprojects",
                timeout=30
            )
            response.raise_for_status()
            projects = response.json()
            
            # Handle different response formats
            if isinstance(projects, dict):
                # Try common response wrappers
                projects = (
                    projects.get('data', []) or
                    projects.get('Data', []) or
                    projects.get('projects', []) or
                    projects.get('Projects', []) or
                    projects.get('result', [])
                )
            
            # Ensure we have a list
            if not isinstance(projects, list):
                self.logger.warning(f"Unexpected response format: {type(projects)}")
                return []
            
            self.logger.info(f"Retrieved {len(projects)} projects")
            return projects
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to retrieve projects list: {e}")
            return []
    
    def find_project_by_name(self, project_name: str, exact_match: bool = False) -> Optional[Dict[str, Any]]:
        """Find a project by name.
        
        Args:
            project_name: The name of the project to search for
            exact_match: If True, only return exact matches. If False, return first partial match.
            
        Returns:
            Project dictionary if found, None otherwise
        """
        projects = self.list_projects()
        
        if not projects:
            self.logger.warning("No projects found")
            return None
        
        # Try exact match first
        for project in projects:
            # Try different possible field names for project name
            name = (
                project.get('name', '') or
                project.get('Name', '') or
                project.get('projectName', '') or
                project.get('ProjectName', '')
            )
            
            if exact_match:
                if name == project_name:
                    guid = self._extract_project_guid(project)
                    self.logger.info(f"Found exact match: {name} (GUID: {guid})")
                    return project
            else:
                if project_name.lower() in name.lower():
                    guid = self._extract_project_guid(project)
                    self.logger.info(f"Found match: {name} (GUID: {guid})")
                    return project
        
        self.logger.warning(f"No project found matching: {project_name}")
        return None
    
    def _extract_project_guid(self, project: Dict[str, Any]) -> str:
        """Extract GUID from project dictionary, trying various field names.
        
        Args:
            project: Project dictionary
            
        Returns:
            Project GUID or 'N/A' if not found
        """
        # Try various possible field names for GUID
        guid = (
            project.get('guid', '') or
            project.get('Guid', '') or
            project.get('projectGuid', '') or
            project.get('ProjectGuid', '') or
            project.get('threatModelGuid', '') or
            project.get('ThreatModelGuid', '') or
            project.get('diagramGuid', '') or
            project.get('DiagramGuid', '') or
            project.get('id', '') or
            project.get('Id', '')
        )
        
        # Log all available keys for debugging
        if not guid or not isinstance(guid, str) or len(guid) < 10:
            self.logger.debug(f"Available project fields: {list(project.keys())}")
            self.logger.debug(f"Project data: {project}")
        
        return guid if guid else 'N/A'
    
    def search_projects(self, query: str) -> List[Dict[str, Any]]:
        """Search for projects by name (case-insensitive partial match).
        
        Args:
            query: Search query string
            
        Returns:
            List of matching project dictionaries
        """
        projects = self.list_projects()
        query_lower = query.lower()
        
        matches = []
        for p in projects:
            # Try different possible field names
            name = (
                p.get('name', '') or
                p.get('Name', '') or
                p.get('projectName', '') or
                p.get('ProjectName', '')
            )
            if query_lower in name.lower():
                matches.append(p)
        
        self.logger.info(f"Found {len(matches)} projects matching '{query}'")
        return matches


# ============================================================================
# MITRE ATT&CK Data Fetcher
# ============================================================================

class MITREAttackFetcher:
    """Fetches and caches MITRE ATT&CK data."""
    
    def __init__(self, stix_url: str, cache_dir: Path, cache_expiry_days: int = 7):
        """Initialize MITRE ATT&CK data fetcher.
        
        Args:
            stix_url: URL to MITRE ATT&CK STIX data
            cache_dir: Directory to cache downloaded data
            cache_expiry_days: Number of days before cache expires
        """
        self.stix_url = stix_url
        self.cache_dir = cache_dir
        self.cache_expiry_days = cache_expiry_days
        self.logger = logging.getLogger(__name__)
        
        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.techniques = {}
        self.tactics = {}
        self.technique_to_tactic = {}
    
    def _get_cache_file(self) -> Path:
        """Get the path to the cache file."""
        return self.cache_dir / 'mitre_attack_data.pkl'
    
    def _is_cache_valid(self) -> bool:
        """Check if cached data is still valid.
        
        Returns:
            True if cache exists and is not expired
        """
        cache_file = self._get_cache_file()
        if not cache_file.exists():
            return False
        
        # Check file age
        file_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
        expiry_time = datetime.now() - timedelta(days=self.cache_expiry_days)
        
        return file_time > expiry_time
    
    def load_data(self, force_refresh: bool = False) -> bool:
        """Load MITRE ATT&CK data from cache or download fresh.
        
        Args:
            force_refresh: Force download even if cache is valid
            
        Returns:
            True if data loaded successfully
        """
        cache_file = self._get_cache_file()
        
        # Try to load from cache
        if not force_refresh and self._is_cache_valid():
            try:
                self.logger.info("Loading MITRE ATT&CK data from cache")
                with open(cache_file, 'rb') as f:
                    cached_data = pickle.load(f)
                    self.techniques = cached_data['techniques']
                    self.tactics = cached_data['tactics']
                    self.technique_to_tactic = cached_data['technique_to_tactic']
                self.logger.info(f"Loaded {len(self.techniques)} techniques and {len(self.tactics)} tactics")
                return True
            except Exception as e:
                self.logger.warning(f"Failed to load cache: {e}. Will download fresh data.")
        
        # Download fresh data
        return self._download_and_parse()
    
    def _download_and_parse(self) -> bool:
        """Download and parse MITRE ATT&CK STIX data.
        
        Returns:
            True if successful
        """
        try:
            self.logger.info(f"Downloading MITRE ATT&CK data from {self.stix_url}")
            response = requests.get(self.stix_url, timeout=60)
            response.raise_for_status()
            
            stix_data = response.json()
            self.logger.info("Parsing MITRE ATT&CK STIX data")
            
            # Parse STIX objects
            objects = stix_data.get('objects', [])
            
            # Extract tactics
            for obj in objects:
                if obj.get('type') == 'x-mitre-tactic':
                    tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    self.tactics[tactic_id] = {
                        'id': tactic_id,
                        'name': obj.get('name', ''),
                        'description': obj.get('description', ''),
                        'shortname': obj.get('x_mitre_shortname', '')
                    }
            
            # Extract techniques
            for obj in objects:
                if obj.get('type') == 'attack-pattern':
                    ext_refs = obj.get('external_references', [])
                    technique_id = ext_refs[0].get('external_id', '') if ext_refs else ''
                    
                    if technique_id:
                        self.techniques[technique_id] = {
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'platforms': obj.get('x_mitre_platforms', []),
                            'tactics': [],
                            'url': ext_refs[0].get('url', '') if ext_refs else ''
                        }
                        
                        # Map to tactics
                        kill_chain_phases = obj.get('kill_chain_phases', [])
                        for phase in kill_chain_phases:
                            if phase.get('kill_chain_name') == 'mitre-attack':
                                tactic_name = phase.get('phase_name', '')
                                self.techniques[technique_id]['tactics'].append(tactic_name)
                                
                                if technique_id not in self.technique_to_tactic:
                                    self.technique_to_tactic[technique_id] = []
                                self.technique_to_tactic[technique_id].append(tactic_name)
            
            self.logger.info(f"Parsed {len(self.techniques)} techniques and {len(self.tactics)} tactics")
            
            # Cache the data
            self._save_to_cache()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to download/parse MITRE ATT&CK data: {e}")
            return False
    
    def _save_to_cache(self):
        """Save parsed data to cache file."""
        try:
            cache_file = self._get_cache_file()
            with open(cache_file, 'wb') as f:
                pickle.dump({
                    'techniques': self.techniques,
                    'tactics': self.tactics,
                    'technique_to_tactic': self.technique_to_tactic
                }, f)
            self.logger.info(f"Cached MITRE ATT&CK data to {cache_file}")
        except Exception as e:
            self.logger.warning(f"Failed to cache data: {e}")
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get technique details by ID.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., 'T1190')
            
        Returns:
            Technique dictionary or None
        """
        return self.techniques.get(technique_id)
    
    def search_techniques(self, query: str) -> List[Dict[str, Any]]:
        """Search techniques by name or description.
        
        Args:
            query: Search query string
            
        Returns:
            List of matching techniques
        """
        query_lower = query.lower()
        results = []
        
        for tech_id, tech_data in self.techniques.items():
            if (query_lower in tech_data['name'].lower() or 
                query_lower in tech_data['description'].lower()):
                results.append(tech_data)
        
        return results


# ============================================================================
# OpenAI API Client Wrapper
# ============================================================================

class OpenAIAttackPathGenerator:
    """Wrapper for OpenAI API to generate attack paths."""
    
    def __init__(self, api_key: str, model: str = 'gpt-4', 
                 max_tokens: int = 2000, temperature: float = 0.7):
        """Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key
            model: Model to use (gpt-4 or gpt-3.5-turbo)
            max_tokens: Maximum tokens for completion
            temperature: Sampling temperature (0-1)
        """
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.logger = logging.getLogger(__name__)
    
    def test_connection(self) -> bool:
        """Test the OpenAI API connection.
        
        Returns:
            True if connection successful
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=5
            )
            self.logger.info("Successfully connected to OpenAI API")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to OpenAI API: {e}")
            return False
    
    def generate_attack_paths(self, threat_data: Dict[str, Any], 
                            mitre_techniques: List[Dict[str, Any]],
                            num_paths: int = 3) -> Optional[Dict[str, Any]]:
        """Generate attack paths for a given threat.
        
        Args:
            threat_data: Threat information from ThreatModeler
            mitre_techniques: Related MITRE ATT&CK techniques
            num_paths: Number of attack paths to generate
            
        Returns:
            Generated attack paths as structured dictionary
        """
        prompt = self._build_prompt(threat_data, mitre_techniques, num_paths)
        
        try:
            self.logger.debug(f"Generating attack paths for threat: {threat_data.get('name', 'Unknown')}")
            self.logger.debug(f"Using {len(mitre_techniques)} MITRE techniques")
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in threat modeling and attack path analysis. You provide detailed, realistic attack scenarios based on MITRE ATT&CK framework. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            content = response.choices[0].message.content or "{}"
            self.logger.debug(f"OpenAI response length: {len(content)} characters")
            
            # Extract JSON if wrapped in markdown code blocks
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]  # Remove ```json
            elif content.startswith("```"):
                content = content[3:]  # Remove ```
            if content.endswith("```"):
                content = content[:-3]  # Remove trailing ```
            content = content.strip()
            
            result = json.loads(content)
            num_paths = len(result.get('attack_paths', []))
            self.logger.info(f"Successfully generated {num_paths} attack paths")
            
            return result
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse OpenAI JSON response: {e}")
            self.logger.debug(f"Response content: {content[:500]}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to generate attack paths: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return None
    
    def _build_prompt(self, threat_data: Dict[str, Any], 
                     mitre_techniques: List[Dict[str, Any]], 
                     num_paths: int) -> str:
        """Build the prompt for OpenAI API.
        
        Args:
            threat_data: Threat information
            mitre_techniques: Related MITRE techniques
            num_paths: Number of paths to generate
            
        Returns:
            Formatted prompt string
        """
        techniques_str = "\n".join([
            f"- {t['id']}: {t['name']} - {t['description'][:200]}..."
            for t in mitre_techniques[:10]  # Limit to avoid token overflow
        ])
        
        prompt = f"""Given the following threat information from a system threat model:

Threat Name: {threat_data.get('name', 'Unknown')}
Threat Category: {threat_data.get('category', 'Unknown')}
Description: {threat_data.get('description', 'No description provided')}
Severity: {threat_data.get('severity', 'Unknown')}

And these mapped MITRE ATT&CK techniques:
{techniques_str if techniques_str else 'No specific techniques mapped'}

Generate {num_paths} realistic attack paths that an adversary might use to exploit this threat.

For each attack path, provide:
1. Attack Path Name (concise, descriptive)
2. Step-by-step attack sequence (4-7 steps)
3. MITRE ATT&CK Technique ID for each step (if applicable)
4. Required attacker capabilities
5. Likelihood score (1-10) with justification
6. Potential impact

IMPORTANT: Respond ONLY with valid JSON. Do not include any text before or after the JSON.

Use this exact JSON structure:
{{
  "attack_paths": [
    {{
      "name": "string",
      "likelihood_score": number,
      "likelihood_justification": "string",
      "impact": "string",
      "attacker_capabilities": ["string"],
      "steps": [
        {{
          "step_number": number,
          "description": "string",
          "mitre_technique_id": "string or null",
          "mitre_technique_name": "string or null",
          "tactic": "string or null"
        }}
      ]
    }}
  ]
}}"""
        
        return prompt


# ============================================================================
# Main Application Class
# ============================================================================

class AttackPathSimulator:
    """Main application class for attack path simulation."""
    
    def __init__(self, config: Config):
        """Initialize the attack path simulator.
        
        Args:
            config: Application configuration
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize clients
        self.threatmodeler_client = ThreatModelerClient(
            config.threatmodeler_api_url,
            config.threatmodeler_api_key
        )
        
        self.mitre_fetcher = MITREAttackFetcher(
            config.mitre_stix_url,
            config.mitre_cache_dir,
            config.mitre_cache_expiry_days
        )
        
        self.openai_generator = OpenAIAttackPathGenerator(
            config.openai_api_key,
            config.openai_model,
            config.openai_max_tokens,
            config.openai_temperature
        )
        
        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
    
    def initialize(self) -> bool:
        """Initialize all components and test connections.
        
        Returns:
            True if initialization successful
        """
        self.logger.info("Initializing Attack Path Simulator...")
        
        # Test ThreatModeler connection
        if not self.threatmodeler_client.test_connection():
            return False
        
        # Load MITRE ATT&CK data
        if not self.mitre_fetcher.load_data():
            return False
        
        # Test OpenAI connection
        if not self.openai_generator.test_connection():
            return False
        
        self.logger.info("✓ All components initialized successfully")
        return True
    
    def generate_attack_paths(self, project_guid: Optional[str] = None, project_name: Optional[str] = None) -> Dict[str, Any]:
        """Generate attack paths for a ThreatModeler project.
        
        Args:
            project_guid: ThreatModeler project GUID (optional if project_name provided)
            project_name: ThreatModeler project name (optional if project_guid provided)
            
        Returns:
            Results dictionary with attack paths
        """
        # If project_name provided, look up the GUID
        if project_name and not project_guid:
            self.logger.info(f"Looking up project by name: {project_name}")
            project_info = self.threatmodeler_client.find_project_by_name(project_name)
            if not project_info:
                self.logger.error(f"Could not find project: {project_name}")
                return {}
            guid_value = self.threatmodeler_client._extract_project_guid(project_info)
            if not guid_value or guid_value == 'N/A':
                self.logger.error("Project found but has no GUID")
                return {}
            project_guid = str(guid_value)
            self.logger.info(f"Found project GUID: {project_guid}")
        
        if not project_guid:
            self.logger.error("Either project_guid or project_name must be provided")
            return {}
        
        self.logger.info(f"Starting attack path generation for project: {project_guid}")
        
        # Fetch project data
        project = self.threatmodeler_client.get_project(project_guid)
        if not project:
            self.logger.error("Failed to retrieve project")
            return {}
        
        # Extract project name from nested structure
        project_name_value = 'Unknown'
        if isinstance(project, dict):
            if 'Data' in project:
                data = project.get('Data', {})
                project_name_value = data.get('Name', data.get('name', 'Unknown'))
            else:
                project_name_value = project.get('threatModelName', project.get('name', 'Unknown'))
        
        # Fetch components
        components = self.threatmodeler_client.get_project_components(project_guid)
        self.logger.info(f"Retrieved {len(components)} components")
        
        # Fetch threats
        threats = self.threatmodeler_client.get_project_threats(project_guid)
        if not threats:
            self.logger.warning("No threats found in project")
            self.logger.info("Note: This could mean either:")
            self.logger.info("  1. The project has no threats defined")
            self.logger.info("  2. The threats are in a different response field")
            self.logger.info("  3. Run with --log-level DEBUG to see the actual response structure")
            return {
                'project_summary': {
                    'project_guid': project_guid,
                    'project_name': project_name_value,
                    'analysis_date': datetime.now().isoformat(),
                    'total_components': len(components),
                    'total_threats': 0,
                    'components_with_threats': 0
                },
                'components': [],
                'threats_by_component': {},
                'attack_paths': [],
                'summary': {
                    'total_threats_analyzed': 0,
                    'total_attack_paths_generated': 0,
                    'high_risk_paths': 0
                }
            }
        
        # Build component summary
        component_summary = []
        for comp in components:
            component_summary.append({
                'name': comp.get('Name', comp.get('FullName', 'Unknown')),
                'type': comp.get('type', comp.get('category', 'Unknown')),
                'id': comp.get('Id', comp.get('id', 'Unknown'))
            })
        
        # Build threat summary grouped by component
        threats_by_component = {}
        
        # Log first threat structure for debugging
        if threats and len(threats) > 0:
            self.logger.debug(f"Sample threat keys: {list(threats[0].keys())[:20]}")
            self.logger.debug(f"Sample threat data: {str(threats[0])[:500]}")
        
        for threat in threats:
            # Extract component name with various fallback fields
            component_name = (
                threat.get('componentName') or 
                threat.get('ComponentName') or
                threat.get('component') or
                threat.get('Component') or
                'Unknown Component'
            )
            
            # Extract threat details with various fallback fields
            threat_info = {
                'name': (
                    threat.get('name') or 
                    threat.get('Name') or 
                    threat.get('threatName') or 
                    threat.get('ThreatName') or
                    threat.get('title') or
                    'Unnamed Threat'
                ),
                'description': (
                    threat.get('description') or 
                    threat.get('Description') or
                    threat.get('text') or
                    threat.get('Text') or
                    threat.get('details') or
                    'No description available'
                )[:500],  # Limit description length
                'severity': (
                    threat.get('severity') or 
                    threat.get('Severity') or
                    threat.get('riskLevel') or 
                    threat.get('RiskLevel') or
                    threat.get('risk') or
                    'Unknown'
                ),
                'status': (
                    threat.get('status') or 
                    threat.get('Status') or
                    threat.get('state') or
                    'Unknown'
                ),
                'id': (
                    threat.get('id') or
                    threat.get('Id') or
                    threat.get('threatId') or
                    'N/A'
                )
            }
            
            # Group threats by component
            if component_name not in threats_by_component:
                threats_by_component[component_name] = []
            threats_by_component[component_name].append(threat_info)
        
        results = {
            'project_summary': {
                'project_guid': project_guid,
                'project_name': project_name_value,
                'analysis_date': datetime.now().isoformat(),
                'total_components': len(components),
                'total_threats': len(threats),
                'components_with_threats': len(threats_by_component)
            },
            'components': component_summary,
            'threats_by_component': threats_by_component,
            'attack_paths': [],
            'summary': {
                'total_threats_analyzed': len(threats),
                'total_attack_paths_generated': 0,
                'high_risk_paths': 0
            }
        }
        
        # Determine how many threats to process
        max_threats_to_process = self.config.max_threats_to_process
        if max_threats_to_process <= 0:
            max_threats_to_process = len(threats)  # Process all threats
        else:
            max_threats_to_process = min(max_threats_to_process, len(threats))
        
        threats_to_process = threats[:max_threats_to_process]
        self.logger.info(f"Processing {len(threats_to_process)} of {len(threats)} threats with {self.config.max_workers} parallel workers...")
        
        # Thread-safe counter and lock for progress tracking
        progress_lock = threading.Lock()
        processed_count = [0]  # Use list for mutability in nested function
        
        def process_threat(threat_data):
            """Process a single threat (designed to run in parallel)."""
            idx, threat = threat_data
            threat_name = threat.get('name', f'Threat {idx}')
            
            with progress_lock:
                processed_count[0] += 1
                current = processed_count[0]
            
            self.logger.info(f"[{current}/{len(threats_to_process)}] Processing: {threat_name}")
            
            # Extract threat details for better context
            threat_context = {
                'name': threat_name,
                'category': threat.get('category', 'Unknown'),
                'type': threat.get('type', 'Unknown'),
                'description': threat.get('description', threat.get('text', 'No description available')),
                'severity': threat.get('severity', threat.get('riskLevel', 'Unknown')),
                'component': threat.get('componentName', 'Unknown')
            }
            
            self.logger.debug(f"Threat context: {threat_context}")
            
            # TODO: Phase 2 - Implement threat-to-technique mapping
            # For now, use sample techniques
            sample_techniques = list(self.mitre_fetcher.techniques.values())[:5]
            
            # Generate attack paths
            self.logger.debug(f"Calling OpenAI generator with {len(sample_techniques)} techniques")
            attack_paths = self.openai_generator.generate_attack_paths(
                threat_context,
                sample_techniques,
                self.config.max_attack_paths_per_threat
            )
            
            self.logger.debug(f"OpenAI response type: {type(attack_paths)}")
            threat_results = []
            if attack_paths:
                self.logger.debug(f"Attack paths keys: {attack_paths.keys() if isinstance(attack_paths, dict) else 'Not a dict'}")
                paths_list = attack_paths.get('attack_paths', [])
                self.logger.info(f"✓ [{current}/{len(threats_to_process)}] Generated {len(paths_list)} attack paths for: {threat_name}")
                
                for path in paths_list:
                    path['threat_name'] = threat_name
                    path['threat_severity'] = threat_context.get('severity', 'Unknown')
                    threat_results.append(path)
            else:
                self.logger.warning(f"✗ [{current}/{len(threats_to_process)}] No attack paths generated for: {threat_name}")
            
            return threat_results
        
        # Process threats in parallel using ThreadPoolExecutor
        self.logger.info(f"Starting parallel processing with {self.config.max_workers} workers...")
        all_paths = []
        
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_threat = {
                executor.submit(process_threat, (idx + 1, threat)): threat 
                for idx, threat in enumerate(threats_to_process)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_threat):
                threat = future_to_threat[future]
                try:
                    paths = future.result()
                    all_paths.extend(paths)
                except Exception as e:
                    threat_name = threat.get('name', 'Unknown')
                    self.logger.error(f"Error processing threat '{threat_name}': {e}")
        
        # Add all generated paths to results
        results['attack_paths'].extend(all_paths)
        self.logger.info(f"✓ Parallel processing complete: {len(all_paths)} total attack paths generated")
        
        # Update summary
        results['summary']['total_attack_paths_generated'] = len(results['attack_paths'])
        results['summary']['high_risk_paths'] = sum(
            1 for p in results['attack_paths'] 
            if p.get('likelihood_score', 0) >= 7
        )
        
        self.logger.info(f"✓ Generated {len(results['attack_paths'])} attack paths")
        return results
    
    def export_results(self, results: Dict[str, Any], output_format: str = 'json',
                      output_file: Optional[str] = None):
        """Export results to file.
        
        Args:
            results: Attack path results
            output_format: Output format (json, csv, markdown)
            output_file: Optional output file name
        """
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"attack_paths_{timestamp}.{output_format}"
        
        output_path = self.config.output_dir / output_file
        
        try:
            if output_format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2)
            
            elif output_format == 'csv':
                # Flatten attack paths for CSV
                rows = []
                for path in results.get('attack_paths', []):
                    for step in path.get('steps', []):
                        rows.append({
                            'threat_name': path.get('threat_name'),
                            'attack_path_name': path.get('name'),
                            'likelihood_score': path.get('likelihood_score'),
                            'step_number': step.get('step_number'),
                            'step_description': step.get('description'),
                            'mitre_technique_id': step.get('mitre_technique_id'),
                            'tactic': step.get('tactic')
                        })
                df = pd.DataFrame(rows)
                df.to_csv(output_path, index=False)
            
            self.logger.info(f"✓ Results exported to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")


# ============================================================================
# Command Line Interface
# ============================================================================

def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description='Attack Path Simulator - Generate attack paths using MITRE ATT&CK and AI'
    )
    
    # Project identification (either GUID or name required)
    project_group = parser.add_mutually_exclusive_group()
    project_group.add_argument(
        '--project-guid',
        help='ThreatModeler project GUID'
    )
    project_group.add_argument(
        '--project-name',
        help='ThreatModeler project name (will search for matching project)'
    )
    
    parser.add_argument(
        '--list-projects',
        action='store_true',
        help='List all available projects and exit'
    )
    parser.add_argument(
        '--search-projects',
        metavar='QUERY',
        help='Search for projects by name and exit'
    )
    parser.add_argument(
        '--output-format',
        choices=['json', 'csv', 'markdown'],
        default='json',
        help='Output format for results'
    )
    parser.add_argument(
        '--output-file',
        help='Output file name (optional)'
    )
    parser.add_argument(
        '--env-file',
        help='Path to .env file (default: .env)'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    parser.add_argument(
        '--force-refresh-mitre',
        action='store_true',
        help='Force refresh of MITRE ATT&CK data cache'
    )
    
    args = parser.parse_args()
    
    # Set up logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 70)
    logger.info("Attack Path Simulator v1.0.0")
    logger.info("=" * 70)
    
    # Load configuration
    config = Config(args.env_file)
    if not config.validate():
        logger.error("Configuration validation failed. Check your .env file.")
        sys.exit(1)
    
    # Initialize simulator
    simulator = AttackPathSimulator(config)
    if not simulator.initialize():
        logger.error("Failed to initialize simulator")
        sys.exit(1)
    
    # Handle list/search commands
    if args.list_projects:
        projects = simulator.threatmodeler_client.list_projects()
        if projects:
            logger.info("\n" + "=" * 70)
            logger.info("AVAILABLE PROJECTS")
            logger.info("=" * 70)
            for i, project in enumerate(projects, 1):
                proj_id = simulator.threatmodeler_client._extract_project_guid(project)
                proj_name = (
                    project.get('name', '') or
                    project.get('Name', '') or
                    project.get('projectName', '') or
                    project.get('ProjectName', 'Unnamed')
                )
                logger.info(f"{i}. {proj_name}")
                logger.info(f"   GUID: {proj_id}")
            logger.info("=" * 70)
        else:
            logger.warning("No projects found")
        sys.exit(0)
    
    if args.search_projects:
        matches = simulator.threatmodeler_client.search_projects(args.search_projects)
        if matches:
            logger.info("\n" + "=" * 70)
            logger.info(f"SEARCH RESULTS FOR: '{args.search_projects}'")
            logger.info("=" * 70)
            for i, project in enumerate(matches, 1):
                proj_id = simulator.threatmodeler_client._extract_project_guid(project)
                proj_name = (
                    project.get('name', '') or
                    project.get('Name', '') or
                    project.get('projectName', '') or
                    project.get('ProjectName', 'Unnamed')
                )
                logger.info(f"{i}. {proj_name}")
                logger.info(f"   GUID: {proj_id}")
            logger.info("=" * 70)
        else:
            logger.warning(f"No projects found matching: {args.search_projects}")
        sys.exit(0)
    
    # Validate that either project_guid or project_name is provided
    if not args.project_guid and not args.project_name:
        logger.error("Either --project-guid or --project-name must be provided (or use --list-projects / --search-projects)")
        sys.exit(1)
    
    # Generate attack paths
    results = simulator.generate_attack_paths(
        project_guid=args.project_guid,
        project_name=args.project_name
    )
    
    if results:
        # Export results
        simulator.export_results(results, args.output_format, args.output_file)
        
        # Print summary
        logger.info("\n" + "=" * 70)
        logger.info("SUMMARY")
        logger.info("=" * 70)
        
        # Project information
        project_summary = results.get('project_summary', {})
        logger.info(f"Project: {project_summary.get('project_name', 'Unknown')}")
        logger.info(f"Project GUID: {project_summary.get('project_guid', 'Unknown')}")
        logger.info(f"Analysis Date: {project_summary.get('analysis_date', 'Unknown')}")
        logger.info("")
        
        # Components and threats
        logger.info(f"Total Components: {project_summary.get('total_components', 0)}")
        logger.info(f"Components with Threats: {project_summary.get('components_with_threats', 0)}")
        logger.info(f"Total Threats: {project_summary.get('total_threats', 0)}")
        logger.info("")
        
        # Attack paths
        logger.info(f"Threats Analyzed: {results['summary']['total_threats_analyzed']}")
        logger.info(f"Attack Paths Generated: {results['summary']['total_attack_paths_generated']}")
        logger.info(f"High Risk Paths (Likelihood ≥7): {results['summary']['high_risk_paths']}")
        logger.info("=" * 70)
    else:
        logger.error("No results generated")
        sys.exit(1)


if __name__ == '__main__':
    main()
