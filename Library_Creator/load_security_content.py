#!/usr/bin/env python3
"""
ThreatModeler Security Content Loader
Loads security content from CSV files into ThreatModeler libraries
"""

import os
import csv
import json
import argparse
import requests
import urllib3
from datetime import datetime
from dotenv import load_dotenv

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables (override any existing env vars)
load_dotenv(override=True)

class ThreatModelerLoader:
    # Risk level mapping: severity to risk ID and name
    RISK_LEVELS = {
        'critical': (1, 'Very High'),
        'very high': (1, 'Very High'),
        'high': (2, 'High'),
        'medium': (3, 'Medium'),
        'low': (4, 'Low'),
        'very low': (5, 'Very Low')
    }
    
    def __init__(self):
        self.base_url = os.getenv('THREATMODELER_BASE_URL')
        self.api_key = os.getenv('THREATMODELER_API_KEY')
        self.accept_language = os.getenv('ACCEPT_LANGUAGE', 'en')
        self.api_path_prefix = os.getenv('API_PATH_PREFIX', '')
        
        if not self.base_url or not self.api_key:
            raise ValueError("Missing required environment variables: THREATMODELER_BASE_URL and/or THREATMODELER_API_KEY")
        
        self.headers = {
            'X-ThreatModeler-ApiKey': self.api_key,
            'Accept-Language': self.accept_language,
            'Content-Type': 'application/json'
        }
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Cache for entities created/found during this session to avoid duplicates
        # Key format: "library_id:entity_type:name_lower" -> entity object
        self.entity_cache = {}
    
    def _make_request(self, method, endpoint, data=None, params=None):
        """Make HTTP request to ThreatModeler API"""
        url = f"{self.base_url}{self.api_path_prefix}{endpoint}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, verify=False)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, params=params, verify=False)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error making {method} request to {endpoint}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
            raise
    
    def get_libraries(self):
        """Get all available libraries"""
        print("Fetching available libraries...")
        try:
            response = self._make_request('GET', '/api/library/libraries')
            
            if response.get('isSuccess'):
                # API returns libraries in 'data' field, not 'result'
                libraries = response.get('data', response.get('result', []))
                print(f"Found {len(libraries)} libraries")
                return libraries
            else:
                print(f"API returned: isSuccess={response.get('isSuccess')}")
                print(f"Full response: {json.dumps(response, indent=2)}")
                return []
        except Exception as e:
            print(f"Error fetching libraries: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def get_entity_types(self):
        """Get all entity type names"""
        print("Fetching entity types...")
        response = self._make_request('GET', '/api/library/entities')
        
        if response.get('isSuccess'):
            result = response.get('result', [])
            # Handle both list and dict responses
            if isinstance(result, list):
                entity_types = result
            elif isinstance(result, dict):
                entity_types = [result]
            else:
                entity_types = []
            
            print(f"Found {len(entity_types)} entity types")
            return entity_types
        return []
    
    def normalize_entity_type_name(self, entity_type):
        """Normalize entity type name for API calls (remove spaces)"""
        # Map display names to API entity type names
        entity_type_map = {
            'Security Requirement': 'SecurityRequirement',
            'Test Case': 'TestCase',
            'Component': 'Component',
            'Threat': 'Threat',
            'Property': 'Property',
            'Compliance Framework': 'ComplianceFramework'
        }
        return entity_type_map.get(entity_type, entity_type.replace(' ', ''))
    
    def map_risk_level(self, severity):
        """Map severity string to risk ID and name"""
        if not severity:
            return 1, 'Very High'  # Default
        severity_lower = severity.strip().lower()
        return self.RISK_LEVELS.get(severity_lower, (1, 'Very High'))
    
    def build_labels(self, *values):
        """Build comma-separated labels from provided values"""
        labels = [v.strip() for v in values if v and v.strip()]
        return ', '.join(labels)
    
    def validate_csv_structure(self, csv_file, mode='relationships'):
        """
        Validate CSV file structure and check for required columns
        
        Args:
            csv_file: Path to CSV file
            mode: 'relationships' for complex loading, 'custom' for simple entity loading
        
        Returns:
            tuple: (is_valid, errors, warnings, column_info)
                - is_valid: Boolean indicating if the file is valid
                - errors: List of error messages (blocking issues)
                - warnings: List of warning messages (non-blocking issues)
                - column_info: Dict with column analysis
        
        Raises:
            FileNotFoundError: If CSV file doesn't exist
        """
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
        
        errors = []
        warnings = []
        column_info = {
            'total_columns': 0,
            'present_columns': [],
            'missing_required': [],
            'missing_optional': [],
            'empty_columns': [],
            'row_count': 0,
            'empty_rows': 0
        }
        
        # Define required and optional columns based on mode
        if mode == 'relationships':
            required_columns = ['Library', 'Component', 'Threat', 'SecurityRequirement']
            optional_columns = [
                'ComponentDescription', 'ThreatDescription', 'SecurityRequirementDescription',
                'Category', 'ThreatCategory', 'Severity', 'ThreatSeverity', 'STRIDE', 'Mitigation',
                'Priority', 'SecurityRequirementPriority', 'SecurityRequirementCategory', 'SRCategory',
                'Standard', 'ComplianceStandard', 'TestCase', 'TestCaseDescription',
                'Property', 'PropertyValue'
            ]
        else:
            # For custom mode, we can't validate specific columns since they're user-defined
            # Just do basic structure checks
            required_columns = []
            optional_columns = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                # Get columns from the CSV
                csv_columns = reader.fieldnames or []
                column_info['total_columns'] = len(csv_columns)
                column_info['present_columns'] = list(csv_columns)
                
                # Check for empty file
                if not csv_columns:
                    errors.append("CSV file has no columns/headers")
                    return False, errors, warnings, column_info
                
                # Check for duplicate column names
                duplicate_cols = [col for col in csv_columns if csv_columns.count(col) > 1]
                if duplicate_cols:
                    errors.append(f"Duplicate column names found: {set(duplicate_cols)}")
                
                # Check for unnamed/empty column headers
                empty_headers = [i for i, col in enumerate(csv_columns) if not col or not col.strip()]
                if empty_headers:
                    warnings.append(f"Empty column headers found at positions: {[i+1 for i in empty_headers]}")
                
                # For relationships mode, check required columns
                if mode == 'relationships' and required_columns:
                    for req_col in required_columns:
                        if req_col not in csv_columns:
                            column_info['missing_required'].append(req_col)
                            errors.append(f"Required column missing: '{req_col}'")
                    
                    # Check optional columns and note which are missing
                    for opt_col in optional_columns:
                        if opt_col not in csv_columns:
                            column_info['missing_optional'].append(opt_col)
                
                # Read all rows to check for data issues
                rows = list(reader)
                column_info['row_count'] = len(rows)
                
                if column_info['row_count'] == 0:
                    errors.append("CSV file has no data rows")
                    return False, errors, warnings, column_info
                
                # Analyze column content
                column_empty_count = {col: 0 for col in csv_columns}
                
                for idx, row in enumerate(rows, 1):
                    # Check if entire row is empty
                    if all(not val or not val.strip() for val in row.values()):
                        column_info['empty_rows'] += 1
                        warnings.append(f"Row {idx} is completely empty")
                        continue
                    
                    # Count empty values per column
                    for col in csv_columns:
                        if not row.get(col, '').strip():
                            column_empty_count[col] += 1
                
                # Identify columns that are completely empty
                for col, empty_count in column_empty_count.items():
                    if empty_count == column_info['row_count']:
                        column_info['empty_columns'].append(col)
                        warnings.append(f"Column '{col}' is completely empty across all rows")
                    elif empty_count > 0 and mode == 'relationships' and col in required_columns:
                        warnings.append(f"Required column '{col}' has {empty_count}/{column_info['row_count']} empty values")
                
                # Check if too many empty rows
                if column_info['empty_rows'] > column_info['row_count'] * 0.5:
                    warnings.append(f"More than 50% of rows are empty ({column_info['empty_rows']}/{column_info['row_count']})")
        
        except UnicodeDecodeError as e:
            errors.append(f"File encoding error: {e}. File may not be UTF-8 encoded.")
            return False, errors, warnings, column_info
        except csv.Error as e:
            errors.append(f"CSV parsing error: {e}")
            return False, errors, warnings, column_info
        except Exception as e:
            errors.append(f"Unexpected error reading CSV: {e}")
            return False, errors, warnings, column_info
        
        # Determine if valid (no blocking errors)
        is_valid = len(errors) == 0
        
        return is_valid, errors, warnings, column_info
    
    def print_validation_report(self, is_valid, errors, warnings, column_info):
        """Print a formatted validation report"""
        print("\n" + "=" * 80)
        print("CSV VALIDATION REPORT")
        print("=" * 80)
        
        # Overall status
        status_symbol = "✓" if is_valid else "✗"
        status_text = "VALID" if is_valid else "INVALID"
        print(f"\nStatus: {status_symbol} {status_text}")
        
        # File statistics
        print(f"\nFile Statistics:")
        print(f"  • Total columns: {column_info['total_columns']}")
        print(f"  • Total rows: {column_info['row_count']}")
        if column_info['empty_rows'] > 0:
            print(f"  • Empty rows: {column_info['empty_rows']}")
        
        # Columns present
        if column_info['present_columns']:
            print(f"\nColumns Present ({len(column_info['present_columns'])}):")
            for col in column_info['present_columns']:
                marker = " (empty)" if col in column_info['empty_columns'] else ""
                print(f"  • {col}{marker}")
        
        # Missing required columns
        if column_info['missing_required']:
            print(f"\n✗ Missing Required Columns ({len(column_info['missing_required'])}):")
            for col in column_info['missing_required']:
                print(f"  • {col}")
        
        # Missing optional columns (if any, just note them)
        if column_info['missing_optional'] and len(column_info['missing_optional']) <= 5:
            print(f"\nMissing Optional Columns ({len(column_info['missing_optional'])}):")
            for col in column_info['missing_optional'][:5]:
                print(f"  • {col}")
        elif len(column_info.get('missing_optional', [])) > 5:
            print(f"\nMissing Optional Columns: {len(column_info['missing_optional'])} (not shown)")
        
        # Errors
        if errors:
            print(f"\n✗ ERRORS ({len(errors)}):")
            for i, error in enumerate(errors, 1):
                print(f"  {i}. {error}")
        
        # Warnings
        if warnings:
            print(f"\n⚠ WARNINGS ({len(warnings)}):")
            for i, warning in enumerate(warnings, 1):
                print(f"  {i}. {warning}")
        
        print("\n" + "=" * 80)
        
        return is_valid
    
    def get_library_by_name(self, library_name):
        """Find library by name"""
        libraries = self.get_libraries()
        for lib in libraries:
            if lib.get('name', '').lower() == library_name.lower():
                return lib
        return None
    
    def search_entity_by_name(self, library_id, entity_type, name):
        """Search for an entity by name in a library"""
        endpoint = '/api/library/getrecords'
        
        # Normalize entity type name for API
        api_entity_type = self.normalize_entity_type_name(entity_type)
        
        payload = {
            "libraryId": library_id,
            "entityTypeName": api_entity_type,
            "pageSize": 1000,  # Get large batch to search
            "pageNumber": 1
        }
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            
            if response.get('isSuccess'):
                records = response.get('result', {}).get('libraryRecords', [])
                print(f"  → Searched {len(records)} {entity_type}(s) in library {library_id}")
                for record in records:
                    if record.get('name', '').lower().strip() == name.lower().strip():
                        return record
        except Exception as e:
            print(f"  Warning: Error searching for {entity_type}: {e}")
        
        return None
    
    def _create_via_update(self, library_id, entity_type, entity_data):
        """Try creating an entity using updaterecords endpoint with isAddition=True"""
        endpoint = '/api/library/updaterecords'
        
        # Normalize entity type name for API
        api_entity_type = self.normalize_entity_type_name(entity_type)
        
        payload = {
            "libraryId": library_id,
            "entityTypeName": api_entity_type,
            "model": json.dumps([entity_data]),
            "isAddition": True
        }
        
        print(f"Creating {entity_type} via updaterecords: {entity_data.get('name', 'Unknown')}")
        print(f"  → Using Library ID: {library_id}")
        
        try:
            response = self._make_request('PUT', endpoint, data=payload)
            
            if response.get('isSuccess'):
                result = response.get('data', response.get('result'))
                
                if isinstance(result, list) and len(result) > 0:
                    entity_id = result[0].get('id')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    return result[0]
                elif isinstance(result, dict):
                    entity_id = result.get('id')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    return result
                elif isinstance(result, str):
                    entity_id = result.strip('[]')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    return {'id': int(entity_id), 'name': entity_data.get('name')}
                else:
                    print(f"  ✓ {entity_type} created (result format unknown)")
                    return {'name': entity_data.get('name')}
            else:
                # Failed - return None so we can try another method
                return None
        except Exception as e:
            # Failed - return None so we can try another method
            return None
    
    def create_entity(self, library_id, entity_type, entity_data):
        """Create a new entity in a library"""
        endpoint = '/api/library/addrecords'
        
        # Normalize entity type name for API (remove spaces)
        api_entity_type = self.normalize_entity_type_name(entity_type)
        
        # API expects the entity data as a JSON array string in the 'model' field
        payload = {
            "libraryId": library_id,
            "entityTypeName": api_entity_type,
            "model": json.dumps([entity_data]),  # Stringify as array
            "isAddition": True
        }
        
        print(f"Creating {entity_type}: {entity_data.get('name', 'Unknown')}")
        print(f"  → Using Library ID: {library_id}")
        print(f"  → DEBUG Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            
            if response.get('isSuccess'):
                # Check both 'data' and 'result' fields
                result = response.get('data', response.get('result'))
                
                print(f"  API result type: {type(result)}, value: {result}")
                
                # The result might be an array, a single object, or a string/GUID
                if isinstance(result, list) and len(result) > 0:
                    entity_id = result[0].get('id')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    return result[0]
                elif isinstance(result, dict):
                    entity_id = result.get('id')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    return result
                elif isinstance(result, str):
                    # API returned ID in format "[5789]"
                    # Extract the ID from the brackets
                    entity_id = result.strip('[]')
                    print(f"  ✓ Successfully created {entity_type} (ID: {entity_id})")
                    # Return a minimal object with the ID
                    return {'id': int(entity_id), 'name': entity_data.get('name')}
                else:
                    print(f"  ✓ Successfully created {entity_type}")
                    return result
            else:
                error_msg = response.get('errorMessage') or response.get('message') or 'Unknown error'
                print(f"  ✗ Failed to create {entity_type}: {error_msg}")
                print(f"  Response: {json.dumps(response, indent=2)}")
                return None
        except Exception as e:
            print(f"  ✗ Exception creating {entity_type}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_or_create_entity(self, library_id, entity_type, entity_data):
        """Get existing entity by name or create new one"""
        name = entity_data.get('name')
        if not name:
            print(f"  ✗ No name provided for {entity_type}")
            return None
        
        # Check local cache first (for this script run)
        cache_key = f"{library_id}:{entity_type}:{name.lower()}"
        if cache_key in self.entity_cache:
            cached = self.entity_cache[cache_key]
            entity_id = cached.get('id')
            print(f"  → Using cached {entity_type}: {name} (ID: {entity_id})")
            return cached
        
        # Try to find existing entity in library
        existing = self.search_entity_by_name(library_id, entity_type, name)
        if existing:
            entity_id = existing.get('id')
            print(f"  → Found existing {entity_type}: {name} (ID: {entity_id})")
            # Cache it for future rows
            self.entity_cache[cache_key] = existing
            return existing
        
        # Create new entity
        print(f"  → Creating new {entity_type}: {name}")
        created = self.create_entity(library_id, entity_type, entity_data)
        if created:
            # Cache the newly created entity
            self.entity_cache[cache_key] = created
        return created
    
    def get_properties(self, library_id):
        """Get all properties for a library"""
        endpoint = '/api/library/getrecords'
        
        payload = {
            "libraryId": library_id,
            "entityTypeName": "Property",
            "pageSize": 1000,
            "pageNumber": 1
        }
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                return response.get('result', {}).get('libraryRecords', [])
        except Exception as e:
            print(f"  Warning: Error fetching properties: {e}")
        
        return []
    
    def search_property_by_name(self, library_id, property_name):
        """Search for a property by name"""
        properties = self.get_properties(library_id)
        for prop in properties:
            if prop.get('name', '').lower() == property_name.lower():
                return prop
        return None
    
    def get_property_options(self, property_id):
        """Get options for a property"""
        endpoint = f'/api/library/property/{property_id}'
        
        try:
            response = self._make_request('GET', endpoint)
            if response.get('isSuccess'):
                result = response.get('result', response.get('data', {}))
                return result.get('options', [])
        except Exception as e:
            print(f"  Warning: Error fetching property options: {e}")
        
        return []
    
    def search_property_option(self, property_id, option_name):
        """Search for a specific property option by name"""
        options = self.get_property_options(property_id)
        for option in options:
            if option.get('name', '').lower() == option_name.lower():
                return option
        return None
    
    def get_component_relationships(self, component_id):
        """Fetch existing relationships for a component"""
        endpoint = '/api/library/getentityreltionshipsrecords'
        
        payload = {
            "entityTypeName": "Component",
            "id": component_id
        }
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                data = response.get('data', {})
                return {
                    'threats': data.get('threats', []),
                    'securityRequirements': data.get('securityRequirements', []),
                    'properties': data.get('properties', [])
                }
        except Exception as e:
            print(f"  Warning: Error fetching component relationships: {e}")
        
        return {'threats': [], 'securityRequirements': [], 'properties': []}
    
    def merge_threat_relationships(self, existing_threats, new_threats_data):
        """Merge new threats with existing threats, avoiding duplicates"""
        # Build a map of existing threat IDs to their full data
        threat_map = {}
        for threat in existing_threats:
            threat_id = threat.get('id')
            threat_map[threat_id] = {
                'threat': threat,
                'security_requirements': set()
            }
            # Collect existing SR IDs for this threat
            for sr in threat.get('securityRequirements', []):
                threat_map[threat_id]['security_requirements'].add(sr.get('id'))
        
        # Merge new threats
        for new_threat in new_threats_data:
            threat_id = new_threat['id']
            if threat_id not in threat_map:
                # New threat - add it
                threat_map[threat_id] = {
                    'threat': {'id': threat_id},
                    'security_requirements': set(new_threat.get('security_requirements', []))
                }
            else:
                # Existing threat - merge security requirements
                threat_map[threat_id]['security_requirements'].update(
                    new_threat.get('security_requirements', [])
                )
        
        return threat_map
    
    def merge_property_relationships(self, existing_properties, new_properties_data):
        """Merge new properties with existing properties, avoiding duplicates"""
        # Build a map of existing property IDs to their data
        property_map = {}
        for prop in existing_properties:
            prop_id = prop.get('id')
            property_map[prop_id] = {
                'property': prop,
                'options': {}  # Map of option_id -> threat_ids set
            }
            # Collect existing property options and their threat associations
            for option in prop.get('options', []):
                option_id = option.get('id')
                property_map[prop_id]['options'][option_id] = set(
                    t.get('id') for t in option.get('threats', [])
                )
        
        # Merge new properties
        for new_prop in new_properties_data:
            prop_id = new_prop['id']
            option_id = new_prop.get('option_id')
            threat_ids = set(new_prop.get('threat_ids', []))
            
            if prop_id not in property_map:
                # New property - add it
                property_map[prop_id] = {
                    'property': {'id': prop_id},
                    'options': {option_id: threat_ids} if option_id else {}
                }
            else:
                # Existing property - merge option threat associations
                if option_id:
                    if option_id not in property_map[prop_id]['options']:
                        property_map[prop_id]['options'][option_id] = threat_ids
                    else:
                        property_map[prop_id]['options'][option_id].update(threat_ids)
        
        return property_map
    
    def create_unified_relationships(self, component_id, library_id, threats_data=None, properties_data=None, merge_with_existing=True):
        """
        Create all relationships using the unified SaveComponentRelationshipDetails API
        
        Args:
            component_id: Component ID
            library_id: Library ID
            threats_data: List of dicts with {id, security_requirements: [id]}
            properties_data: List of dicts with {id, option_id, threat_ids: []}
            merge_with_existing: If True, fetch and merge with existing relationships
            
        Returns:
            bool: Success status
        """
        endpoint = '/api/library/SaveComponentRelationshipDetails'
        
        # Fetch existing relationships if merge is enabled
        threat_map = {}
        property_map = {}
        
        if merge_with_existing:
            print(f"  → Fetching existing relationships for Component {component_id}")
            existing = self.get_component_relationships(component_id)
            
            # Merge threats
            if threats_data:
                threat_map = self.merge_threat_relationships(existing['threats'], threats_data)
                print(f"    • Merged {len(threat_map)} unique threats")
            else:
                # No new threats, just preserve existing
                threat_map = self.merge_threat_relationships(existing['threats'], [])
            
            # Merge properties
            if properties_data:
                property_map = self.merge_property_relationships(existing['properties'], properties_data)
                print(f"    • Merged {len(property_map)} unique properties")
            else:
                # No new properties, just preserve existing
                property_map = self.merge_property_relationships(existing['properties'], [])
        else:
            # No merge - use only new data
            if threats_data:
                threat_map = self.merge_threat_relationships([], threats_data)
            if properties_data:
                property_map = self.merge_property_relationships([], properties_data)
        
        payload = {
            "id": component_id,
            "libraryId": library_id
        }
        
        # Build threats array with nested security requirements
        if threat_map:
            payload["threats"] = []
            key_counter = -2  # Start with -2 for new relationships
            
            for threat_id, threat_info in threat_map.items():
                threat_payload = {
                    "Id": threat_id,
                    "Key": key_counter,
                    "Type": "Threat"
                }
                key_counter -= 1
                
                # Add security requirements if present
                if threat_info['security_requirements']:
                    threat_payload["securityRequirements"] = []
                    for sr_id in threat_info['security_requirements']:
                        sr_payload = {
                            "Id": sr_id,
                            "Key": key_counter,
                            "Type": "SecurityRequirement",
                            "usedForMitigation": True
                        }
                        threat_payload["securityRequirements"].append(sr_payload)
                        key_counter -= 1
                
                payload["threats"].append(threat_payload)
        
        # Build properties array with options and threat associations
        if property_map:
            payload["properties"] = []
            key_counter = -3  # Start with -3 for properties
            
            for prop_id, prop_info in property_map.items():
                prop_payload = {
                    "Id": prop_id,
                    "Key": key_counter,
                    "Type": "Property"
                }
                key_counter -= 1
                
                # Add property options with threat associations
                if prop_info['options']:
                    prop_payload["options"] = []
                    for option_id, threat_ids in prop_info['options'].items():
                        option_payload = {
                            "Id": option_id,
                            "threats": []
                        }
                        # Link property option to threats
                        for threat_id in threat_ids:
                            option_payload["threats"].append({
                                "Id": threat_id,
                                "Type": "Threat"
                            })
                        prop_payload["options"].append(option_payload)
                
                payload["properties"].append(prop_payload)
        
        print(f"  → Saving unified relationships for Component {component_id}")
        print(f"    • Total threats: {len(payload.get('threats', []))}")
        print(f"    • Total properties: {len(payload.get('properties', []))}")
        print(f"  → DEBUG Unified Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                print(f"    ✓ Successfully created all relationships")
                return True
            else:
                error_msg = response.get('errorMessage', 'Unknown error')
                print(f"    ✗ Failed to create relationships: {error_msg}")
                return False
        except Exception as e:
            print(f"    ✗ Exception creating relationships: {e}")
            return False
    
    def link_component_to_threat(self, component_id, threat_id):
        """Link a component to a threat"""
        endpoint = '/api/library/SaveComponentRelationshipDetails'
        
        payload = {
            "id": component_id,
            "threats": [{"id": threat_id}]
        }
        
        print(f"  → Linking Component {component_id} to Threat {threat_id}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                print(f"    ✓ Successfully linked")
                return True
            else:
                print(f"    ✗ Failed to link: {response.get('errorMessage', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"    ✗ Exception linking: {e}")
            return False
    
    def link_threat_to_security_requirement(self, threat_id, security_req_id):
        """Link a threat to a security requirement using association endpoint"""
        endpoint = '/api/library/association'
        
        payload = {
            "sourceId": threat_id,
            "entityTypeName": self.normalize_entity_type_name("Threat"),
            "action": "add",
            "targets": [{
                "sourceId": security_req_id,
                "entityTypeName": self.normalize_entity_type_name("Security Requirement")
            }]
        }
        
        print(f"  → Linking Threat {threat_id} to Security Requirement {security_req_id}")
        print(f"  → DEBUG Association Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                print(f"    ✓ Successfully linked")
                return True
            else:
                error_msg = response.get('errorMessage') or response.get('message', 'Unknown error')
                print(f"    ✗ Failed to link: {error_msg}")
                return False
        except Exception as e:
            print(f"    ✗ Exception linking: {e}")
            return False
    
    def create_security_requirement_via_threat(self, threat_id, library_id, sec_req_data):
        """Create a security requirement by updating the threat with new SR data"""
        endpoint = '/api/library/SaveThreatSecurityRequirementsTestcases'
        
        # Build the security requirement payload for creation
        sec_req_payload = {
            "name": sec_req_data.get('name'),
            "description": sec_req_data.get('description', ''),
            "riskId": sec_req_data.get('riskId', 1),
            "riskName": sec_req_data.get('riskName', 'Very High'),
            "labels": sec_req_data.get('labels', ''),
            "libraryId": library_id,
            "isHidden": sec_req_data.get('isHidden', False),
            "isEnableAssociation": sec_req_data.get('isEnableAssociation', True)
        }
        
        payload = {
            "id": threat_id,
            "securityRequirements": [sec_req_payload]
        }
        
        print(f"Creating Security Requirement via Threat: {sec_req_data.get('name')}")
        print(f"  → Through Threat ID: {threat_id}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                # The API should return the created SR details
                result = response.get('data', response.get('result'))
                print(f"  ✓ Successfully created Security Requirement via Threat")
                # Try to extract the ID from the result if available
                if isinstance(result, dict):
                    return result
                elif isinstance(result, list) and len(result) > 0:
                    return result[0]
                else:
                    # Return a basic object with the name
                    return {'name': sec_req_data.get('name')}
            else:
                error_msg = response.get('errorMessage') or response.get('message', 'Unknown error')
                print(f"  ✗ Failed to create Security Requirement via Threat: {error_msg}")
                print(f"  Response: {json.dumps(response, indent=2)}")
                return None
        except Exception as e:
            print(f"  ✗ Exception creating Security Requirement via Threat: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_test_case_via_threat(self, threat_id, library_id, test_case_data):
        """Create a test case by updating the threat with new test case data"""
        endpoint = '/api/library/SaveThreatSecurityRequirementsTestcases'
        
        # Build the test case payload for creation
        test_case_payload = {
            "name": test_case_data.get('name'),
            "description": test_case_data.get('description', ''),
            "libraryId": library_id,
            "isHidden": test_case_data.get('isHidden', False)
        }
        
        payload = {
            "id": threat_id,
            "testCases": [test_case_payload]
        }
        
        print(f"Creating Test Case via Threat: {test_case_data.get('name')}")
        print(f"  → Through Threat ID: {threat_id}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                # The API should return the created test case details
                result = response.get('data', response.get('result'))
                print(f"  ✓ Successfully created Test Case via Threat")
                # Try to extract the ID from the result if available
                if isinstance(result, dict):
                    return result
                elif isinstance(result, list) and len(result) > 0:
                    return result[0]
                else:
                    # Return a basic object with the name
                    return {'name': test_case_data.get('name')}
            else:
                error_msg = response.get('errorMessage') or response.get('message', 'Unknown error')
                print(f"  ✗ Failed to create Test Case via Threat: {error_msg}")
                print(f"  Response: {json.dumps(response, indent=2)}")
                return None
        except Exception as e:
            print(f"  ✗ Exception creating Test Case via Threat: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def link_threat_to_test_case(self, threat_id, test_case_id):
        """Link a threat to a test case using association endpoint"""
        endpoint = '/api/library/association'
        
        payload = {
            "sourceId": threat_id,
            "entityTypeName": self.normalize_entity_type_name("Threat"),
            "action": "add",
            "targets": [{
                "sourceId": test_case_id,
                "entityTypeName": self.normalize_entity_type_name("Test Case")
            }]
        }
        
        print(f"  → Linking Threat {threat_id} to Test Case {test_case_id}")
        print(f"  → DEBUG Association Payload: {json.dumps(payload, indent=2)}")
        
        try:
            response = self._make_request('POST', endpoint, data=payload)
            if response.get('isSuccess'):
                print(f"    ✓ Successfully linked")
                return True
            else:
                error_msg = response.get('errorMessage') or response.get('message', 'Unknown error')
                print(f"    ✗ Failed to link: {error_msg}")
                return False
        except Exception as e:
            print(f"    ✗ Exception linking: {e}")
            return False
    
    def load_relationships_from_csv(self, csv_file, dry_run=False):
        """
        Load entities and relationships from CSV file (left-to-right processing)
        
        Expected CSV columns (order matters):
        - Library: Library name
        - Component: Component name
        - ComponentDescription: Component description (optional)
        - Threat: Threat name
        - ThreatDescription: Threat description (optional)
        - ThreatCategory, Severity, STRIDE, Mitigation: Threat metadata (optional)
        - SecurityRequirement: Security requirement name
        - SecurityRequirementDescription: Security requirement description (optional)
        - Priority, SecurityRequirementCategory, Standard: SR metadata (optional)
        - TestCase: Test case name (optional)
        - TestCaseDescription: Test case description (optional)
        - Property: Property name (optional)
        - PropertyValue: Property option/value (optional)
        
        Args:
            csv_file: Path to CSV file
            dry_run: If True, only validate without creating
        """
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
        
        # Validate CSV structure first
        print(f"\nValidating CSV file: {csv_file}")
        is_valid, errors, warnings, column_info = self.validate_csv_structure(csv_file, mode='relationships')
        self.print_validation_report(is_valid, errors, warnings, column_info)
        
        if not is_valid:
            print("\n✗ CSV validation failed. Please fix the errors above before loading.")
            return 0, 0
        
        if warnings and not dry_run:
            print("\n⚠ CSV has warnings but is still valid. Proceeding with loading...")
        
        # Clear entity cache for this new import
        self.entity_cache.clear()
        
        print(f"\nLoading relationships from: {csv_file}")
        print(f"Dry Run: {dry_run}")
        print("=" * 80)
        
        success_count = 0
        failure_count = 0
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            print(f"Found {len(rows)} rows in CSV file")
            if reader.fieldnames:
                print(f"CSV Columns: {list(reader.fieldnames)}")
            print()
            
            for idx, row in enumerate(rows, 1):
                print(f"\n{'='*80}")
                print(f"Processing Row {idx}/{len(rows)}")
                print(f"{'='*80}")
                
                try:
                    if dry_run:
                        print("[DRY RUN MODE]")
                    
                    # Step 1: Get Library
                    library_name = row.get('Library', '').strip()
                    if not library_name:
                        print("  ✗ No library specified, skipping row")
                        failure_count += 1
                        continue
                    
                    print(f"\n1. Library: {library_name}")
                    library = self.get_library_by_name(library_name)
                    if not library:
                        print(f"  ✗ Library '{library_name}' not found")
                        print(f"  Available libraries:")
                        for lib in self.get_libraries():
                            print(f"    - {lib.get('name')} (ID: {lib.get('id')})")
                        failure_count += 1
                        continue
                    library_id = library.get('id')
                    print(f"  ✓ Found Library: {library.get('name')} (ID: {library_id})")
                    
                    if dry_run:
                        print("\n  [Would continue with entity creation and linking]")
                        success_count += 1
                        continue
                    
                    # Step 2: Get/Create Component
                    component_name = row.get('Component', '').strip()
                    component_id = None
                    if component_name:
                        print(f"\n2. Component: {component_name}")
                        component_data = {
                            'name': component_name,
                            'description': row.get('ComponentDescription', '').strip() or component_name,
                            'componentTypeId': 3,  # Standard component type
                            'componentTypeName': 'Component',
                            'isHidden': False,
                            'resourceTypeName': '',
                            'libraryId': library_id  # Ensure component is created in correct library
                        }
                        component = self.get_or_create_entity(library_id, 'Component', component_data)
                        if component:
                            component_id = component.get('id')
                        else:
                            print(f"  ✗ Failed to get/create component")
                            failure_count += 1
                            continue
                    
                    # Step 3: Get/Create Threat
                    threat_name = row.get('Threat', '').strip()
                    threat_id = None
                    if threat_name:
                        print(f"\n3. Threat: {threat_name}")
                        
                        # Enhanced metadata extraction
                        category = row.get('Category', row.get('ThreatCategory', '')).strip()
                        severity = row.get('Severity', row.get('ThreatSeverity', '')).strip()
                        stride = row.get('STRIDE', '').strip()
                        mitigation = row.get('Mitigation', '').strip()
                        
                        # Map severity to risk level
                        risk_id, risk_name = self.map_risk_level(severity)
                        
                        # Build labels from metadata
                        labels = self.build_labels(category, stride)
                        
                        # Build description with enhanced info
                        description = row.get('ThreatDescription', '').strip() or threat_name
                        if mitigation:
                            description += f"\n\nMitigation: {mitigation}"
                        
                        threat_data = {
                            'name': threat_name,
                            'description': description,
                            'riskId': risk_id,
                            'riskName': risk_name,
                            'labels': labels,
                            'isHidden': False,
                            'isEnableAssociation': True,
                            'readonly': False,
                            'libraryId': library_id  # Ensure threat is created in correct library
                        }
                        
                        # Add custom fields for additional metadata
                        if category:
                            threat_data['customField1'] = category
                        if stride:
                            threat_data['customField2'] = stride
                        
                        print(f"  → Risk Level: {risk_name} ({risk_id})")
                        if labels:
                            print(f"  → Labels: {labels}")
                        
                        threat = self.get_or_create_entity(library_id, 'Threat', threat_data)
                        if threat:
                            threat_id = threat.get('id')
                        else:
                            print(f"  ✗ Failed to get/create threat")
                            failure_count += 1
                            continue
                    
                    # Step 4: Create Security Requirement in library (don't link yet)
                    sec_req_name = row.get('SecurityRequirement', '').strip()
                    sec_req_id = None
                    if sec_req_name and threat_id:
                        print(f"\n4. Security Requirement: {sec_req_name}")
                        
                        # Enhanced metadata extraction
                        priority = row.get('Priority', row.get('SecurityRequirementPriority', '')).strip()
                        sr_category = row.get('SecurityRequirementCategory', row.get('SRCategory', '')).strip()
                        standard = row.get('Standard', row.get('ComplianceStandard', '')).strip()
                        
                        # Map priority to risk level
                        risk_id, risk_name = self.map_risk_level(priority) if priority else (1, 'Very High')
                        
                        # Build labels from metadata
                        labels = self.build_labels(sr_category, standard)
                        
                        sec_req_data = {
                            'name': sec_req_name,
                            'description': row.get('SecurityRequirementDescription', '').strip() or sec_req_name,
                            'riskId': risk_id,
                            'riskName': risk_name,
                            'labels': labels,
                            'isHidden': False,
                            'isEnableAssociation': True,
                            'libraryId': library_id  # Ensure SR is created in correct library
                        }
                        
                        print(f"  → Priority/Risk: {risk_name} ({risk_id})")
                        if labels:
                            print(f"  → Labels: {labels}")
                        # Try to create as standalone library entity first
                        sec_req = self.get_or_create_entity(library_id, 'Security Requirement', sec_req_data)
                        if sec_req:
                            sec_req_id = sec_req.get('id')
                        else:
                            # Fallback: try creating via threat relationship
                            print(f"  → Falling back to creation via threat...")
                            sec_req = self.create_security_requirement_via_threat(threat_id, library_id, sec_req_data)
                            if sec_req:
                                sec_req_id = sec_req.get('id')
                                print(f"  ✓ Security Requirement created via threat")
                            else:
                                print(f"  ✗ Failed to create security requirement")
                    elif sec_req_name and not threat_id:
                        print(f"\n4. Security Requirement: {sec_req_name}")
                        print(f"  ⚠ Skipping - no threat to attach it to")
                    
                    # Step 5: Handle Properties and Property Options
                    property_name = row.get('Property', '').strip()
                    property_value = row.get('PropertyValue', '').strip()
                    property_id = None
                    property_option_id = None
                    
                    if property_name:
                        print(f"\n5. Property: {property_name}")
                        property = self.search_property_by_name(library_id, property_name)
                        if property:
                            property_id = property.get('id')
                            print(f"  → Found Property (ID: {property_id})")
                            
                            # Look for specific property value/option
                            if property_value:
                                print(f"  → Looking for Property Value: {property_value}")
                                option = self.search_property_option(property_id, property_value)
                                if option:
                                    property_option_id = option.get('id')
                                    print(f"  ✓ Found Property Option (ID: {property_option_id})")
                                else:
                                    print(f"  ⚠ Property value '{property_value}' not found")
                        else:
                            print(f"  ⚠ Property '{property_name}' not found in library")
                    
                    # Step 6: Create Test Case in library, then link to Threat
                    test_case_name = row.get('TestCase', '').strip()
                    test_case_id = None
                    if test_case_name and threat_id:
                        print(f"\n6. Test Case: {test_case_name}")
                        test_case_data = {
                            'name': test_case_name,
                            'description': row.get('TestCaseDescription', '').strip() or test_case_name,
                            'isHidden': False,
                            'libraryId': library_id  # Ensure test case is created in correct library
                        }
                        # Try to create as standalone library entity first
                        test_case = self.get_or_create_entity(library_id, 'Test Case', test_case_data)
                        if test_case:
                            test_case_id = test_case.get('id')
                        else:
                            # Fallback: try creating via threat relationship
                            print(f"  → Falling back to creation via threat...")
                            test_case = self.create_test_case_via_threat(threat_id, library_id, test_case_data)
                            if test_case:
                                test_case_id = test_case.get('id')
                                print(f"  ✓ Test Case created via threat")
                            else:
                                print(f"  ✗ Failed to create test case")
                    elif test_case_name and not threat_id:
                        print(f"\n6. Test Case: {test_case_name}")
                        print(f"  ⚠ Skipping - no threat to attach it to")
                    
                    # Step 7: Create all relationships using unified API (with automatic merge)
                    if component_id:
                        print(f"\n7. Creating Unified Relationships")
                        
                        # Build threats data structure
                        threats_data = []
                        if threat_id:
                            threat_entry = {
                                'id': threat_id,
                                'security_requirements': []
                            }
                            if sec_req_id:
                                threat_entry['security_requirements'].append(sec_req_id)
                            threats_data.append(threat_entry)
                        
                        # Build properties data structure
                        properties_data = []
                        if property_id and property_option_id:
                            prop_entry = {
                                'id': property_id,
                                'option_id': property_option_id,
                                'threat_ids': [threat_id] if threat_id else []
                            }
                            properties_data.append(prop_entry)
                        
                        # Call unified relationship creation (merge_with_existing=True by default)
                        # This will fetch existing relationships and merge new ones, preventing duplicates
                        if threats_data or properties_data:
                            success = self.create_unified_relationships(
                                component_id,
                                library_id,
                                threats_data=threats_data if threats_data else None,
                                properties_data=properties_data if properties_data else None
                            )
                            if not success:
                                print(f"  ⚠ Some relationships may not have been created")
                    
                    print(f"\n✓ Row {idx} processed successfully")
                    success_count += 1
                    
                except Exception as e:
                    print(f"\n✗ Error processing row {idx}: {e}")
                    import traceback
                    traceback.print_exc()
                    failure_count += 1
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total rows: {len(rows)}")
        print(f"Successfully processed: {success_count}")
        print(f"Failed: {failure_count}")
        print(f"Entities cached during run: {len(self.entity_cache)}")
        if dry_run:
            print("\n[DRY RUN] No entities or relationships were created")
        
        return success_count, failure_count
    
    def load_from_csv(self, csv_file, library_id, entity_type, column_mapping, dry_run=False):
        """
        Load entities from CSV file (legacy method for simple entity creation)
        
        Args:
            csv_file: Path to CSV file
            library_id: Target library ID
            entity_type: Entity type name (Component, Threat, Security Requirements, etc.)
            column_mapping: Dict mapping CSV columns to API fields
            dry_run: If True, only validate without creating
        """
        if not os.path.exists(csv_file):
            raise FileNotFoundError(f"CSV file not found: {csv_file}")
        
        # Validate CSV structure first
        print(f"\nValidating CSV file: {csv_file}")
        is_valid, errors, warnings, column_info = self.validate_csv_structure(csv_file, mode='custom')
        self.print_validation_report(is_valid, errors, warnings, column_info)
        
        if not is_valid:
            print("\n✗ CSV validation failed. Please fix the errors above before loading.")
            return [], []
        
        # Check if all required columns from mapping are present
        missing_mapped_cols = []
        for csv_col in column_mapping.keys():
            if csv_col not in column_info['present_columns']:
                missing_mapped_cols.append(csv_col)
        
        if missing_mapped_cols:
            print(f"\n✗ ERROR: Columns specified in mapping are missing from CSV:")
            for col in missing_mapped_cols:
                print(f"  • {col}")
            print("\nAvailable columns in CSV:")
            for col in column_info['present_columns']:
                print(f"  • {col}")
            return [], []
        
        if warnings and not dry_run:
            print("\n⚠ CSV has warnings but is still valid. Proceeding with loading...")
        
        print(f"\nLoading from: {csv_file}")
        print(f"Target Library ID: {library_id}")
        print(f"Entity Type: {entity_type}")
        print(f"Dry Run: {dry_run}")
        print("-" * 80)
        
        entities_created = []
        entities_failed = []
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            print(f"Found {len(rows)} rows in CSV file")
            print(f"CSV Columns: {reader.fieldnames}")
            print()
            
            for idx, row in enumerate(rows, 1):
                print(f"Processing row {idx}/{len(rows)}")
                
                # Build entity data from column mapping
                entity_data = {}
                for csv_col, api_field in column_mapping.items():
                    if csv_col in row:
                        value = row[csv_col].strip()
                        if value:  # Only include non-empty values
                            entity_data[api_field] = value
                
                # Add any unmapped data as custom fields
                entity_data['customFields'] = {}
                for col, val in row.items():
                    if col not in column_mapping and val.strip():
                        entity_data['customFields'][col] = val.strip()
                
                print(f"  Entity data: {json.dumps(entity_data, indent=2)}")
                
                if not dry_run:
                    result = self.create_entity(library_id, entity_type, entity_data)
                    if result:
                        entities_created.append(entity_data)
                    else:
                        entities_failed.append(entity_data)
                else:
                    print(f"  [DRY RUN] Would create: {entity_data.get('name', 'Unknown')}")
                
                print()
        
        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total rows processed: {len(rows)}")
        if not dry_run:
            print(f"Successfully created: {len(entities_created)}")
            print(f"Failed: {len(entities_failed)}")
            
            if entities_failed:
                print("\nFailed entities:")
                for entity in entities_failed:
                    print(f"  - {entity.get('name', 'Unknown')}")
        else:
            print("[DRY RUN] No entities were created")
        
        return entities_created, entities_failed


def main():
    parser = argparse.ArgumentParser(
        description='Load security content from CSV into ThreatModeler',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Validate CSV file structure without loading
  python3 load_security_content.py --validate security_data.csv
  
  # List available libraries
  python3 load_security_content.py --list-libraries
  
  # List available entity types
  python3 load_security_content.py --list-entity-types
  
  # Load with relationships (recommended - left-to-right processing)
  python3 load_security_content.py --csv-relationships security_data.csv
  
  # Dry run with relationships
  python3 load_security_content.py --csv-relationships security_data.csv --dry-run
  
  # Legacy: Load individual entities without relationships
  python3 load_security_content.py --csv threats.csv --library-id 106 \\
    --entity-type "Threat" \\
    --map "Name=name" --map "Description=description"

CSV Format for --csv-relationships:
  Required columns: Library, Component, Threat, SecurityRequirement
  Optional columns: ComponentDescription, ThreatDescription, SecurityRequirementDescription, TestCase, TestCaseDescription
  
  Metadata columns (optional):
    Threat: Category/ThreatCategory, Severity/ThreatSeverity, STRIDE, Mitigation
    Security Requirement: Priority/SecurityRequirementPriority, SecurityRequirementCategory/SRCategory, Standard/ComplianceStandard
    Properties: Property, PropertyValue
  
  Example:
  Library,Component,ComponentDescription,Threat,ThreatDescription,Category,Severity,SecurityRequirement,Priority,Standard
  Security Engineering,Web Server,Customer web application,SQL Injection,Attacker injects SQL,Injection,High,Use Parameterized Queries,Critical,OWASP ASVS 5.3
        '''
    )
    
    parser.add_argument('--validate', type=str, metavar='CSV_FILE',
                       help='Validate CSV file structure without loading data')
    parser.add_argument('--list-libraries', action='store_true',
                       help='List all available libraries')
    parser.add_argument('--list-entity-types', action='store_true',
                       help='List all available entity types')
    parser.add_argument('--csv-relationships', type=str,
                       help='Path to CSV file with relationships (Library, Component, Threat, SecurityRequirement columns)')
    parser.add_argument('--csv', type=str,
                       help='Path to CSV file for legacy entity-only loading')
    parser.add_argument('--library-id', type=int,
                       help='Target library ID (for legacy --csv mode)')
    parser.add_argument('--entity-type', type=str,
                       help='Entity type name (for legacy --csv mode)')
    parser.add_argument('--map', action='append', dest='mappings',
                       help='Column mapping in format "CSVColumn=APIField" (for legacy --csv mode)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Validate CSV without creating entities')
    
    args = parser.parse_args()
    
    try:
        loader = ThreatModelerLoader()
        
        # Validate CSV structure only
        if args.validate:
            if not os.path.exists(args.validate):
                print(f"Error: CSV file not found: {args.validate}")
                return
            
            print(f"Validating CSV file: {args.validate}")
            is_valid, errors, warnings, column_info = loader.validate_csv_structure(
                args.validate, 
                mode='relationships'
            )
            loader.print_validation_report(is_valid, errors, warnings, column_info)
            
            if is_valid:
                print("\n✓ CSV file is valid and ready for import!")
            else:
                print("\n✗ CSV file has errors that must be fixed before import.")
            return
        
        # List libraries
        if args.list_libraries:
            libraries = loader.get_libraries()
            print("\nAvailable Libraries:")
            print("-" * 80)
            for lib in libraries:
                print(f"ID: {lib.get('id')}  |  Name: {lib.get('name')}")
            return
        
        # List entity types
        if args.list_entity_types:
            entity_types = loader.get_entity_types()
            print("\nAvailable Entity Types:")
            print("-" * 80)
            for et in entity_types:
                if isinstance(et, dict):
                    print(f"  - {et.get('entityTypeName', et)}")
                else:
                    print(f"  - {et}")
            return
        
        # Load with relationships (recommended)
        if args.csv_relationships:
            loader.load_relationships_from_csv(
                args.csv_relationships,
                dry_run=args.dry_run
            )
            return
        
        # Legacy: Load from CSV without relationships
        if args.csv:
            if not args.library_id:
                print("Error: --library-id is required when loading from CSV")
                return
            
            if not args.entity_type:
                print("Error: --entity-type is required when loading from CSV")
                return
            
            if not args.mappings:
                print("Error: At least one --map is required when loading from CSV")
                print("Example: --map 'Name=name' --map 'Description=description'")
                return
            
            # Parse column mappings
            column_mapping = {}
            for mapping in args.mappings:
                if '=' not in mapping:
                    print(f"Error: Invalid mapping format: {mapping}")
                    print("Expected format: CSVColumn=APIField")
                    return
                csv_col, api_field = mapping.split('=', 1)
                column_mapping[csv_col] = api_field
            
            print(f"Column mappings: {column_mapping}")
            
            loader.load_from_csv(
                args.csv,
                args.library_id,
                args.entity_type,
                column_mapping,
                dry_run=args.dry_run
            )
        else:
            print("No action specified. Use --list-libraries, --list-entity-types, --csv-relationships, or --csv")
            parser.print_help()
    
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
