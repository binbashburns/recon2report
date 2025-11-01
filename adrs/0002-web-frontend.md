# ADR 0002: Web Frontend

**Status**: Accepted  
**Date**: 2025-10-31  
**Deciders**: @binbashburns

## Overview

Added a static web frontend using Vite + Vanilla JavaScript. Provides visual interface for creating sessions, viewing scan results, and exploring attack vectors.

## Implementation

### Stack

- **Vite** - Dev server and build tool
- **Vanilla JavaScript** - No framework dependencies
- **Custom CSS** - CSS variables for theming
- **Fetch API** - HTTP requests to R2R.Api

### Architecture

```
┌──────────────┐         ┌──────────────┐
│  R2R.Web     │  HTTP   │   R2R.Api    │
│  (Vite)      ├────────→│  (.NET 9)    │
│  Port 5173   │  CORS   │  Port 5258   │
└──────────────┘         └──────────────┘
```

### Running the Frontend

```bash
cd R2R.Web
npm install
npm run dev
```

Browser opens at `http://localhost:5173`

### Project Structure

```
R2R.Web/
├── index.html       # Single-page app structure
├── main.js          # API integration and UI logic
├── style.css        # Styling with CSS variables
└── package.json     # Vite dependency
```

### Screens

1. **Session + Target Form** - Create session with IP/OS
2. **Nmap Suggestions** - Show scan commands from API (`/nmap/suggest`)
3. **Paste Nmap XML** - Upload scan results
4. **Parsed Ports** - Display all hosts with nested port lists, per-host attack vector buttons
5. **Attack Suggestions** - Show phase-based vectors for selected host (`/attack-paths/suggest`)
6. **Attack Vector Reference** - Dictionary view of all vectors by phase with raw syntax (`/attack-paths/all`)

### Key Features

- **Multi-host support** - Single scan displays all discovered hosts
- **Per-host attack vectors** - Each host has its own "Get Attack Vectors" button
- **Reference dictionary** - Browse all attack vectors without filtering by target
- **Nested port display** - Each host card shows ports, services, versions
- **Phase selector** - Switch between recon/creds/lateral/privesc/persistence
- **Click-to-copy** - Copy commands to clipboard
- **Variable substitution** - Commands use actual IPs (not `<ip>` placeholders)

### API Endpoints Used

- `POST /sessions` - Create session
- `POST /targets` - Create target
- `POST /nmap/suggest` - Get scan commands
- `POST /targets/{id}/scan` - Upload Nmap XML
- `POST /attack-paths/suggest` - Get filtered attack vectors for specific host
- `GET /attack-paths/all?phase={phase}` - Get all vectors for reference mode

## Notes

- CORS configured in API for `http://localhost:5173`
- Refreshing page loses state (matches in-memory API design)
- Reference page shows raw command syntax with `<target>`, `<domain>` placeholders
- Attack suggestions page substitutes actual values into commands
- Multi-host scans display all hosts; attack suggestions use first host by default

## Future

- Target selector for multi-host attack suggestions
- Export to markdown/PDF
- Session persistence
- Dark mode

## References

- [ADR 0000: Architecture Overview](./0000-architecture-overview.md)
- [Vite Documentation](https://vitejs.dev/)
