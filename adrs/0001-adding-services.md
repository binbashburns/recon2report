# ADR 0001: Adding New Services

**Status**: Accepted  
**Date**: 2025-10-31  
**Deciders**: @binbashburns

## Context

As new protocols and attack techniques emerge, we need a straightforward way to add them to the system without modifying application code.

## Decision

All attack vectors are defined in **JSON service files** under `/services/`. Each file represents a single service or protocol (e.g., SMB, HTTP, Kerberos).

## JSON Schema

```json
{
  "service": "string",              // Service name (e.g., "SMB", "HTTP")
  "description": "string",          // Brief description
  "ports": [int, int],              // Ports this service runs on
  "serviceNames": ["string"],       // Nmap service names that match
  "targetOs": ["string"],           // "Windows", "Linux", or "Any"
  "vectors": [
    {
      "id": "string",               // Unique identifier (kebab-case)
      "name": "string",             // Display name
      "phase": "string",            // "reconnaissance", "credential_access", etc.
      "prerequisites": ["string"],  // What you need to run this (e.g., ["network_access"])
      "description": "string",      // What this vector does
      "commands": [
        {
          "tool": "string",         // Tool name (e.g., "nmap", "smbclient")
          "syntax": "string",       // Command with placeholders (<ip>, <domain>)
          "description": "string"   // What this command does
        }
      ],
      "outcomes": ["string"]        // What you might obtain (e.g., ["credentials", "admin_access"])
    }
  ]
}
```

## Adding a New Service

### 1. Create the JSON file

```bash
touch services/new-service.json
```

### 2. Define the service metadata

```json
{
  "service": "PostgreSQL",
  "description": "PostgreSQL database attacks",
  "ports": [5432],
  "serviceNames": ["postgresql"],
  "targetOs": ["Any"],
  "vectors": []
}
```

### 3. Add attack vectors

Each vector represents a specific technique:

```json
{
  "id": "psql-default-creds",
  "name": "PostgreSQL Default Credentials",
  "phase": "credential_access",
  "prerequisites": ["network_access"],
  "description": "Test for default PostgreSQL credentials",
  "commands": [
    {
      "tool": "psql",
      "syntax": "psql -h <ip> -U postgres -W",
      "description": "Connect with default postgres user"
    }
  ],
  "outcomes": ["database_access"]
}
```

### 4. Test your service

The API automatically loads all JSON files from `/services/` at startup. Check the console output:

```
Loaded 20 service rule set(s)
  ✓ PostgreSQL: 1 vectors (Ports: 5432)
```

### 5. Verify in Swagger

Use the `/debug/services` endpoint to see all loaded services and their vectors.

## Variable Substitution

The API automatically replaces these placeholders in command syntax:

| Placeholder | Replaced With | Example |
|-------------|---------------|---------|
| `<ip>`, `<target>` | Target IP address | `192.168.1.10` |
| `<domain>` | Domain name | `CORP.LOCAL` |
| `<ip_range>` | IP range | `192.168.1.0/24` |
| `<port>` | Detected open port(s) | `80` or `80,443` |

## Phase Definitions

| Phase | Description | Examples |
|-------|-------------|----------|
| `reconnaissance` | Initial discovery, no credentials | Port scanning, DNS enumeration |
| `credential_access` | Obtaining credentials | Password spraying, hash dumping |
| `lateral_movement` | Moving through network | Pass-the-hash, remote execution |
| `privilege_escalation` | Elevating privileges | UAC bypass, kernel exploits |
| `persistence` | Maintaining access | Backdoors, scheduled tasks |

## Best Practices

###  Do
- Group related attacks in one service file
- Use descriptive `id` values (kebab-case)
- Include helpful `description` fields
- Test your JSON for validity

###  Don't
- Mix multiple unrelated services in one file
- Hardcode IP addresses or domains in commands
- Leave out `prerequisites` (use `[]` for no requirements)
- Forget to specify `targetOs` (use `["Any"]` if applicable)

## Example: Complete Service File

See `/services/smb.json` for a production example with:
- Anonymous enumeration
- Authenticated enumeration
- Vulnerability scanning
- Relay attacks
- Share access

## Consequences

### Positive
-  Non-developers can add new attacks
-  No code changes or recompilation needed
-  Easy to share attack definitions between teams
-  Git-friendly (JSON diffs are readable)

### Negative
-  Must maintain JSON schema consistency
-  No compile-time checking of syntax errors
