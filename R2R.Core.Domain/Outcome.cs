namespace R2R.Core.Domain;

/// <summary>
/// Represents a possible result from executing an attack vector.
/// Maps to arrows/outcomes in markdown (e.g., ">>> Username", ">>> Hash found").
/// </summary>
public record Outcome(
    string StateId,        // Identifier for the resulting state (e.g., "username", "hash_found")
    string DisplayName,    // Human-readable name (e.g., "Username", "Hash found")
    string? Description    // Optional additional context
);
