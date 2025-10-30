# recon2report ⓡ②ⓡ
![img1](./assets/r2r-logo.png)
Better pentesting, from recon to reporting.

## Overview
- **R2R.Api**: ASP.NET Core minimal API that stores session/target data in memory and exposes endpoints for Nmap parsing and rule-based attack path suggestions.
- **R2R.Cli**: Lightweight console client that drives the API workflow from the terminal.
- **R2R.Core.Domain**: Domain models for attack vectors, commands, outcomes, and rule sets.
- **R2R.Core.Parsing**: Markdown parser that converts attack path documentation into structured rule sets. (Credit goes to [@Orange-Cyberdefense](https://github.com/Orange-Cyberdefense) for the [mindmap](https://github.com/Orange-Cyberdefense/ocd-mindmaps/tree/main/excalimap/mindmap/ad) which these rules were derived from!)
- **R2R.Core.Rules**: Rule engine that evaluates current state and suggests applicable attack vectors.
- **R2R.Tests**: xUnit tests covering parsing, rule engine, and Nmap helpers.
- **docs/**: Markdown files defining attack paths and techniques (e.g., `no_creds.md`, `authenticated.md`).

Everything runs in-memory (no persistence yet) so it is ideal for quick lab-style recon exercises.

## Prerequisites
- [.NET 9 SDK](https://dotnet.microsoft.com/) (Preview as of now). `dotnet --version` should report `9.0.*`.

## Getting Started
1. Restore and build once to pull dependencies:
   ```bash
   dotnet restore
   ```
2. Start the API in one terminal:
   ```bash
   dotnet run --project R2R.Api
   ```
   The default launch profile listens on `http://localhost:5258` and exposes OpenAPI JSON at `/openapi/v1.json`.

   ![img2](/assets/step-1.png)
3. Launch the CLI in a separate terminal:
   ```bash
   dotnet run --project R2R.Cli
   ```
   ![img3](/assets/step-2.png)

## Typical Workflow
1. When prompted, name the session and provide the target IP/OS.
2. Review the suggested Nmap commands surfaced by the API.
3. Run any scans you want, then paste the Nmap "normal" output into the CLI and terminate with a single `EOF` line.
4. The CLI displays parsed open ports followed by **rule-based attack path suggestions** from markdown files.
   - Attack vectors are loaded from `/docs/*.md` files at API startup
   - Commands are automatically customized with your target IP, domain, and IP range
   - Suggestions are filtered based on open ports and services
5. Demonstrate CRUD via the optional prompts to update/delete the target.

All data lives in memory; restarting the API clears it.

## Attack Path System

The system uses markdown files in `/docs/` to define attack paths dynamically. This allows you to maintain attack techniques without changing code.

### How It Works
1. **Markdown files** (e.g., `no_creds.md`) define attack phases and techniques
2. **Parser** loads these at API startup into structured rule sets
3. **Rule engine** matches your current state (phase, ports, services) to applicable techniques
4. **Variable substitution** fills in `<ip>`, `<domain>`, `<ip_range>` placeholders with real values

### Example
From `no_creds.md`:
```markdown
## Anonymous SMB access >>> Username
- `smbclient -L //<ip> -N`
- `enum4linux-ng -A <ip>`
```

When you call the API with `targetIp: "192.168.1.5"`, you get:
```json
{
  "name": "Anonymous SMB access",
  "commands": [
    {
      "tool": "smbclient",
      "rawSyntax": "smbclient -L //<ip> -N",
      "readyCommand": "smbclient -L //192.168.1.5 -N"
    }
  ]
}
```

See `/docs/README.md` for complete documentation on maintaining markdown files.

## API Surface
| Method & Path            | Description                                              |
| ------------------------ | -------------------------------------------------------- |
| `POST /sessions`         | Creates a new recon session.                             |
| `GET /sessions/{id}`     | Fetches a previously created session.                    |
| `DELETE /sessions/{id}`  | Removes a session (and implicitly its targets).          |
| `POST /targets`          | Adds a target tied to a session.                         |
| `GET /targets/{id}`      | Retrieves target metadata.                               |
| `PUT /targets/{id}`      | Updates target details.                                  |
| `DELETE /targets/{id}`   | Deletes a target.                                        |
| `POST /targets/{id}/scan`| Uploads and stores parsed Nmap scan results for a target.|
| `GET /targets/{id}/scan` | Retrieves stored scan results for a target.              |
| `POST /nmap/suggest`     | Returns curated Nmap commands for the given IP/OS.       |
| `POST /nmap/parse`       | Parses Nmap "normal" output into `OpenPort` records.     |
| `POST /attack-paths/suggest` | **NEW**: Suggests attack vectors based on current phase, ports, and services using markdown rule sets. |

## Running Tests
```bash
dotnet test
```

## Project Layout
```
R2R.Api/             Minimal API (endpoints + helpers)
R2R.Cli/             Console workflow client
R2R.Core.Domain/     Domain models (AttackVector, Command, Outcome, RuleSet, AttackState)
R2R.Core.Parsing/    Markdown parser for attack path files
R2R.Core.Rules/      Rule engine for evaluating attack states
R2R.Tests/           xUnit test project
docs/                Markdown files defining attack paths (e.g., no_creds.md)
```

## Troubleshooting
- **403 from CLI**: Ensure the API is running and that `R2R_API_BASE` matches its URL (defaults to `http://localhost:5258/`).
- **Swagger/Swashbuckle build errors**: The project relies on `Microsoft.AspNetCore.OpenApi` only; make sure no other Swagger packages are referenced.
- **dotnet test errors**: Confirm the API project builds; missing types are usually due to visibility changes in `Program.cs`.
