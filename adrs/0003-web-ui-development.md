# Web UI Development Guide

## Quick Start (< 5 minutes)

1. **Start the API** (Terminal 1):
   ```bash
   cd R2R.Api
   dotnet run
   ```
   - API runs on: `http://localhost:5258`
   - Swagger UI: `http://localhost:5258/swagger`

2. **Start the Web UI** (Terminal 2):
   ```bash
   cd R2R.Web
   npm install  # First time only
   npm run dev
   ```
   - Web UI runs on: `http://localhost:5173`
   - Opens automatically in your browser

3. **Test the workflow**:
   - Create a session and target
   - Get Nmap suggestions
   - Paste scan XML results
   - View attack vectors

## Configuration

### API URL
The frontend connects to the API at `http://localhost:5258`. To change this:

**File**: `R2R.Web/main.js`
```javascript
const API_BASE = 'http://localhost:5258';  // Line 1
```

### CORS Origins
The API allows requests from `http://localhost:5173` by default.

**File**: `R2R.Api/Program.cs` (lines 13-19)
```csharp
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:5173")  // Add more origins here
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});
```

To allow multiple origins (e.g., production deployment):
```csharp
policy.WithOrigins(
    "http://localhost:5173",
    "https://your-domain.com"
)
```

### Vite Dev Server Port
To change the frontend port from 5173:

**File**: `R2R.Web/vite.config.js` (create if missing)
```javascript
import { defineConfig } from 'vite'

export default defineConfig({
  server: {
    port: 3000  // Your preferred port
  }
})
```

**Remember**: Update CORS origins in the API if you change the frontend port!

## Development Workflow

**Hot Reload**: Both API and frontend support hot reload
- API: Watches for file changes (dotnet watch)
- Frontend: Vite auto-refreshes on save

**Run with hot reload**:
```bash
# Terminal 1 - API with auto-reload
cd R2R.Api
dotnet watch run

# Terminal 2 - Frontend (already has hot reload)
cd R2R.Web
npm run dev
```

## Common Issues

| Issue | Solution |
|-------|----------|
| CORS errors in browser console | Verify API is running and frontend URL matches CORS policy |
| "Failed to fetch" errors | Check API is running on `http://localhost:5258` |
| Web UI shows blank screen | Run `npm install` in R2R.Web, check browser console for errors |
| Port 5173 already in use | Change Vite port in `vite.config.js`, update CORS in API |
| Swagger not loading | Navigate to `http://localhost:5258/swagger` (not /swagger/index.html) |

## Production Build

```bash
cd R2R.Web
npm run build
```
- Outputs to `R2R.Web/dist/`
- Optimized, minified assets
- Serve with any static file server (Nginx, Apache, etc.)

## Architecture

### Frontend Stack
- **Vite**: Fast dev server with hot module replacement
- **Vanilla JavaScript**: No framework dependencies, simple and fast
- **CSS Variables**: Centralized theming for consistent UI

### State Management
- Single `state` object tracks sessions, targets, hosts, and context
- `hostContexts` object stores per-host information (credentials, OS, notes)
- No external state management library needed

### Navigation
- Single-page application with 7 screens
- Two-tier navigation: Main nav + sub-nav for workflow screens
- `goToScreen()` function manages screen transitions

### API Integration
- All API calls use native `fetch()`
- Base URL configurable via `API_BASE` constant
- Automatic variable substitution for attack commands

### Features
- Multi-host support with individual attack vector buttons
- Service-grouped attack vectors (DNS, SMB, HTTP sections)
- Click-to-copy for all commands
- Host context tracking (credentials, domain info, notes)
- Reference dictionary mode for all attack vectors
- Phase-aware filtering
