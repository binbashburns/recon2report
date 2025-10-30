namespace R2R.Core.Domain;

/// <summary>
/// Represents a collection of attack vectors from a single markdown file.
/// Each markdown file (e.g., no_creds.md) becomes one RuleSet.
/// </summary>
public record RuleSet(
    string Id,                      // Unique identifier (filename without extension, e.g., "no_creds")
    string Name,                    // Display name (e.g., "No Credentials")
    string InitialState,            // Starting state for this ruleset (e.g., "no_creds")
    List<AttackVector> Vectors      // All attack vectors in this ruleset
);
