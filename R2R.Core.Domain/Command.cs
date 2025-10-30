namespace R2R.Core.Domain;

/// <summary>
/// Represents a specific tool command with its syntax.
/// Extracted from bullet points in markdown (e.g., "nmap -sP -p <ip>").
/// </summary>
public record Command(
    string Tool,           // Tool name extracted from command (e.g., "nmap", "nxc")
    string Syntax,         // Full command syntax (e.g., "nmap -sP -p <ip>")
    string? Description    // Optional explanation or note
);
