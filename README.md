# recon2report
Better pentesting, from recon to reporting.

## Overview
- **R2R.Api** — ASP.NET Core minimal API that stores session/target data in memory and exposes helper endpoints for Nmap parsing and follow-up suggestions.
- **R2R.Cli** — Lightweight console client that drives the API workflow from the terminal.
- **R2R.Tests** — xUnit tests that cover the parsing/suggestion helpers.

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
3. (Optional) Export a different base URL if you change the API port:
   ```bash
   export R2R_API_BASE=http://localhost:5000/
   ```
4. Launch the CLI in a separate terminal:
   ```bash
   dotnet run --project R2R.Cli
   ```

## Typical Workflow
1. When prompted, name the session and provide the target IP/OS.
2. Review the suggested Nmap commands surfaced by the API.
3. Run any scans you want, then paste the Nmap “normal” output into the CLI and terminate with a single `EOF` line.
4. The CLI displays parsed open ports followed by generalized next-step suggestions tailored to the detected services/OS.
5. Demonstrate CRUD via the optional prompts to update/delete the target.

All data lives in memory; restarting the API clears it.

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
| `POST /nmap/suggest`     | Returns curated Nmap commands for the given IP/OS.       |
| `POST /nmap/parse`       | Parses Nmap “normal” output into `OpenPort` records.     |
| `POST /next-steps`       | Suggests follow-up actions based on OS + open ports.     |

## Running Tests
```bash
dotnet test
```

## Project Layout
```
R2R.Api/     Minimal API (program + helpers)
R2R.Cli/     Console workflow client
R2R.Tests/   xUnit test project
```

## Troubleshooting
- **403 from CLI**: Ensure the API is running and that `R2R_API_BASE` matches its URL (defaults to `http://localhost:5258/`).
- **Swagger/Swashbuckle build errors**: The project relies on `Microsoft.AspNetCore.OpenApi` only; make sure no other Swagger packages are referenced.
- **dotnet test errors**: Confirm the API project builds; missing types are usually due to visibility changes in `Program.cs`.
