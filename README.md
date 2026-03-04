# ThreatModeler
This is a public repo for ThreatModeler API Integrations for managing the configurations and operationalization of the tool

## Contents

- [Repository Structure](#repository-structure)
- [Library Creator](#library-creator)
- [AI Integrations](#ai-integrations)
- [ThreatModeler API Spec](#threatmodeler-api-spec)

## Repository Structure

- `Library_Creator/` – Security content loader and library import tooling. See [Library_Creator/README.md](Library_Creator/README.md)
- `ai_integrations/` – AI-based integrations and utilities. See [ai_integrations/Content_Creation/README.md](ai_integrations/Content_Creation/README.md)
- `threatModeler_api.json` – ThreatModeler API specification (JSON)

## Library Creator

The **Library Creator** is a Python tool for importing security content (Components, Threats, Security Requirements, Test Cases, and relationships) into ThreatModeler libraries.

- Docs: [Library_Creator/README.md](Library_Creator/README.md)

## AI Integrations

The **AI Integrations** folder contains an AI-driven threat modeling system that generates threats, requirements, and test cases from a component description.

- Docs: [ai_integrations/Content_Creation/README.md](ai_integrations/Content_Creation/README.md)

## ThreatModeler API Spec

- `threatModeler_api.json` contains the ThreatModeler API specification used by integrations in this repo.