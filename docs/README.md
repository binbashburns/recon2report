# Attack Path Markdown Files - Maintenance Guide

## Overview
This directory contains markdown files that define attack paths for penetration testing workflows. Each file represents a phase or state in the attack lifecycle (e.g., `no_creds.md`, `authenticated.md`, `admin.md`).

## File Structure Convention

### 1. **Main Title (H1)**
The file must start with an H1 header representing the phase name:
```markdown
# No Credentials
```
This becomes the `InitialState` for the ruleset (normalized to `nocreds`).

### 2. **Attack Vectors (H2)**
Each H2 section represents an attack vector or technique:
```markdown
## Scan network >>> Vulnerable host
```

**Syntax:**
- **Name** (left of `>>>`): The attack technique name (e.g., "Scan network")
- **Outcome** (right of `>>>`): What you might discover (e.g., "Vulnerable host", "Username", "Hash")
- Multiple outcomes can be chained: `>>> Outcome1 >>> Outcome2`

### 3. **Commands (Bullet Lists)**
Commands are listed as bullet points under each H2 section:
```markdown
- `nxc smb <ip_range>`
- `nmap -sP -p <ip>`
- `enum4linux-ng.py -a -u '' -p '' <ip>`
```

**Command Format:**
- Wrap commands in backticks
- Use angle brackets for variables: `<ip>`, `<domain>`, `<ip_range>`, `<dc_ip>`, `<target>`
- The first word is extracted as the tool name (e.g., `nxc`, `nmap`, `kerbrute`)

## Variable Substitution

The API automatically substitutes the following variables in commands:

| Placeholder | Substituted By | API Request Field |
|------------|----------------|-------------------|
| `<ip>`, `<dc_ip>`, `<target>` | Target IP address | `targetIp` |
| `<domain>`, `<domain_name>` | Domain name | `domainName` |
| `<ip_range>` | IP range (e.g., 10.0.0.0/24) | `ipRange` |

**Example:**
- Markdown: `nxc smb <ip_range> -u '' -p ''`
- API Request: `{ "targetIp": "10.10.10.5", "ipRange": "10.10.10.0/24" }`
- Result: `nxc smb 10.10.10.0/24 -u '' -p ''`

## Adding New Attack Paths

### Step 1: Create or Edit Markdown File
```markdown
# New Phase Name

## Attack Vector Name >>> Expected Outcome
- `command1 <ip>`
- `command2 --option <domain>`

## Another Vector >>> Multiple >>> Outcomes
- `tool <ip_range>`
```

### Step 2: Update API Loader (if new file)
Edit `/R2R.Api/Program.cs` to load the new file:
```csharp
var newFile = Path.Combine(docsPath, "new_phase.md");
if (File.Exists(newFile))
{
    var ruleSet = MarkdownRuleLoader.LoadFromFile(newFile);
    ruleSets.Add(ruleSet);
}
```

### Step 3: Test
Restart the API and check console output for:
```
✓ Loaded ruleset: New Phase Name with X attack vectors
```

## Naming Conventions

### Phase Names (filenames)
- Use lowercase with underscores: `no_creds.md`, `dom_admin.md`
- The parser normalizes to: `nocreds`, `domadmin`

### Attack Vector Names
- Use descriptive action phrases: "Scan network", "Anonymous SMB access"
- Avoid special characters except spaces and `&`

### Outcomes
- Use noun phrases: "Username", "Hash found", "Vulnerable host"
- These become navigable states in the attack graph

## Best Practices

1. **Keep commands realistic** - Commands should be copy-pasteable with minimal editing
2. **Group related techniques** - Each H2 should represent a logical attack step
3. **Use consistent variable names** - Stick to `<ip>`, `<domain>`, `<ip_range>`
4. **Document prerequisites** - The H1 title defines what state you need to be in
5. **Chain outcomes** - Use `>>>` to show what each vector might discover

## Testing Your Changes

After editing a markdown file:

1. **Restart the API**
2. **Send a test request**:
```bash
curl -X POST http://localhost:5258/attack-paths/suggest \
  -H "Content-Type: application/json" \
  -d '{
    "currentPhase": "no_creds",
    "targetIp": "10.10.10.5",
    "ipRange": "10.10.10.0/24",
    "openPorts": [445, 139],
    "services": ["smb"]
  }'
```

3. **Verify response** includes your new vectors with substituted variables

## Architecture

```
docs/*.md  →  MarkdownRuleLoader  →  RuleSet objects  →  RuleEngine  →  API Response
```

- **MarkdownRuleLoader**: Parses markdown into structured `RuleSet` objects
- **RuleEngine**: Matches current state to applicable attack vectors
- **API**: Substitutes variables and returns ready-to-execute commands

## Future Enhancements

- Support for conditional commands (e.g., Windows vs Linux)
- State transition tracking (don't suggest already-tried techniques)
- Integration with target/session persistence
- Automatic tool availability checking
