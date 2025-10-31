# ADR 0000: Architecture Overview

**Status**: Accepted  
**Date**: 2025-10-31  
**Deciders**: Core Team

## Context

Penetration testers need a structured way to move from reconnaissance data (Nmap scans) to actionable attack commands, with context-aware suggestions based on what services are running and what access has been obtained.

## Decision

We will build **recon2report** as a service-based attack path suggestion system with these architectural principles:

### Core Architecture

```
┌─────────────────┐
│   R2R.Cli       │  Interactive CLI for pentesters
│  (Console UI)   │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│   R2R.Api       │  RESTful API (ASP.NET Core Minimal API)
│  (HTTP Server)  │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌─────────┐ ┌──────────────┐
│ Parsing │ │ Rule Engine  │
└─────────┘ └──────────────┘
    │              │
    ▼              ▼
┌──────────────────────────┐
│  Service JSON Files      │
│  (smb.json, http.json)   │
└──────────────────────────┘
```

### Key Components

1. **Domain Layer** (`R2R.Core.Domain`)
   - Pure domain models: `AttackVector`, `Command`, `Outcome`, `ServiceRuleSet`
   - No dependencies on infrastructure

2. **Parsing Layer** (`R2R.Core.Parsing`)
   - Loads JSON service definitions from disk
   - Converts DTOs to domain models

3. **Rules Layer** (`R2R.Core.Rules`)
   - `ServiceRuleEngine` filters attack vectors based on:
     - Open ports (only loads relevant services)
     - Current phase (reconnaissance → privilege_escalation)
     - Prerequisites (what items have been acquired)
     - Target OS (Windows/Linux/Any)

4. **API Layer** (`R2R.Api`)
   - Exposes RESTful endpoints
   - In-memory data storage (sessions, targets, scan results)
   - Variable substitution for commands (`<ip>`, `<domain>`, etc.)

5. **CLI Layer** (`R2R.Cli`)
   - Interactive terminal workflow
   - Guides user through scan → parse → suggest cycle

### Service-Based Organization

Attack vectors are organized by **service/protocol** rather than by phase:

- **Port-to-service mapping**: Port 445 → Load `smb.json` only
- **Lazy loading**: Only parse relevant JSON files
- **Clean separation**: All SMB attacks in one file, easy to maintain

## Consequences

### Positive
-  Fast performance (only loads 2-4 services per scan)
-  Easy to maintain (edit JSON without touching code)
-  Accurate suggestions (no irrelevant attack vectors)
-  Testable (clear separation of concerns)

### Negative
-  Requires discipline to keep JSON files well-organized
-  No persistence (in-memory only for Phase 1)

## References
- Service JSON schema in ADR 0001
- Adding new services in ADR 0001
