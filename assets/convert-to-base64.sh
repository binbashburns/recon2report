#!/bin/bash
# Convert an image file to base64 data URL format for evidence upload
# Usage: ./convert-to-base64.sh screenshot.png

if [ $# -eq 0 ]; then
    echo "Usage: $0 <image-file>"
    echo "Example: $0 screenshot.png"
    exit 1
fi

IMAGE_FILE="$1"

if [ ! -f "$IMAGE_FILE" ]; then
    echo "Error: File '$IMAGE_FILE' not found"
    exit 1
fi

# Detect image type from extension
EXT="${IMAGE_FILE##*.}"
case "${EXT,,}" in
    png)
        MIME_TYPE="image/png"
        ;;
    jpg|jpeg)
        MIME_TYPE="image/jpeg"
        ;;
    gif)
        MIME_TYPE="image/gif"
        ;;
    *)
        echo "Error: Unsupported file type. Use PNG, JPG, or GIF"
        exit 1
        ;;
esac

# Get file size
FILE_SIZE=$(stat -f%z "$IMAGE_FILE" 2>/dev/null || stat -c%s "$IMAGE_FILE" 2>/dev/null)
MAX_SIZE=$((5 * 1024 * 1024)) # 5MB

if [ "$FILE_SIZE" -gt "$MAX_SIZE" ]; then
    echo "Warning: File is larger than 5MB ($(($FILE_SIZE / 1024 / 1024))MB)"
    echo "Consider resizing the image before upload"
fi

# Convert to base64 (remove line breaks)
BASE64_DATA=$(base64 < "$IMAGE_FILE" | tr -d '\n')

# Create data URL
DATA_URL="data:${MIME_TYPE};base64,${BASE64_DATA}"

# Output JSON format ready for Swagger
echo ""
echo "=== Ready for Swagger/API ==="
echo ""
echo "{"
echo "  \"targetId\": \"YOUR_TARGET_ID\","
echo "  \"stage\": \"exploitation\","
echo "  \"caption\": \"YOUR_CAPTION_HERE\","
echo "  \"dataUrl\": \"${DATA_URL}\""
echo "}"
echo ""
echo "=== Stats ==="
echo "File: $IMAGE_FILE"
echo "Size: $(($FILE_SIZE / 1024))KB"
echo "Type: $MIME_TYPE"
echo "Base64 length: ${#DATA_URL} characters"
echo ""

# Optionally save to file
OUTPUT_FILE="${IMAGE_FILE%.*}.json"
cat > "$OUTPUT_FILE" << EOF
{
  "targetId": "REPLACE_WITH_TARGET_ID",
  "stage": "exploitation",
  "caption": "REPLACE_WITH_CAPTION",
  "dataUrl": "${DATA_URL}"
}
EOF

echo "✓ Saved to: $OUTPUT_FILE"
echo "Edit the file to add your targetId and caption, then use in Swagger or curl"
