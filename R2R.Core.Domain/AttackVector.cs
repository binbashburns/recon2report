namespace R2R.Core.Domain;

/// <summary>
/// Represents an action or technique that can be performed in a penetration test.
/// Maps to a section in the markdown (e.g., "Scan network", "Zone transfer").
/// </summary>
public record AttackVector(
    string Id,                      // Unique identifier (e.g., "scan_network")
    string Name,                    // Display name (e.g., "Scan network")
    List<string> Prerequisites,     // What state/items you need (e.g., ["no_creds"])
    List<Outcome> PossibleOutcomes, // What you might discover (e.g., "Username", "Vulnerable host")
    List<Command> Commands          // Specific tools/commands to run
);
