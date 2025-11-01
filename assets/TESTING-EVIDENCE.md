# Testing Evidence Upload

## Quick Test with Swagger

The POST /evidence endpoint in Swagger already includes a working example with a small test image.

1. Start the API: `dotnet run --project R2R.Api`
2. Open Swagger: `http://localhost:5258/swagger`
3. Expand `POST /evidence`
4. Click "Try it out"
5. The example request is pre-filled with:
   - A valid target ID (you'll need to create a session and target first)
   - A valid base64 PNG image
   - A stage and caption

## Using Real Screenshots

### Option 1: Convert Script (Recommended)

Use the provided script to convert any image:

```bash
cd assets
chmod +x convert-to-base64.sh
./convert-to-base64.sh your-screenshot.png
```

This creates a `.json` file ready to paste into Swagger:
- Validates image size (warns if > 5MB)
- Validates image type (PNG, JPG, GIF)
- Outputs properly formatted JSON

### Option 2: Manual Conversion

**macOS/Linux:**
```bash
base64 -i screenshot.png | tr -d '\n' > base64.txt
```

**Windows (PowerShell):**
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("screenshot.png")) > base64.txt
```

Then format as:
```
data:image/png;base64,{paste base64.txt contents here}
```

## Testing Workflow

### 1. Create Session
```bash
curl -X POST http://localhost:5258/sessions \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Session", "ipRange": "192.168.1.0/24"}'
```
Save the returned `id` (session ID).

### 2. Create Target
```bash
curl -X POST http://localhost:5258/targets \
  -H "Content-Type: application/json" \
  -d '{"sessionId": "YOUR_SESSION_ID", "ip": "192.168.1.10", "os": "Windows"}'
```
Save the returned `id` (target ID).

### 3. Upload Evidence
Use the target ID in your evidence request:
```bash
curl -X POST http://localhost:5258/evidence \
  -H "Content-Type: application/json" \
  -d @screenshot.json
```

### 4. Retrieve Evidence
```bash
# Get single evidence
curl http://localhost:5258/evidence/EVIDENCE_ID

# Get all evidence for target
curl http://localhost:5258/targets/TARGET_ID/evidence

# Get all evidence for session
curl http://localhost:5258/sessions/SESSION_ID/evidence
```

## Valid Stages

Evidence must have one of these stages (matching OSCP report structure):
- `information_gathering`
- `enumeration`
- `exploitation`
- `privilege_escalation`
- `post_exploitation`
- `maintaining_access`
- `house_cleaning`

## Size Limits

- **Minimum**: 100 bytes (prevents empty/corrupt images)
- **Maximum**: 5MB (prevents memory issues)
- **Recommended**: Resize screenshots to 1920x1080 or smaller before uploading

## Tips

- Use PNG for screenshots (lossless, good compression)
- Use JPG for photos (better compression, slightly lossy)
- Compress images before converting: `pngquant screenshot.png` (macOS: `brew install pngquant`)
- For large uploads, consider resizing: `sips -Z 1920 screenshot.png` (macOS built-in)
