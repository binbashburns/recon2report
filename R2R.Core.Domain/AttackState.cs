namespace R2R.Core.Domain;

/// <summary>
/// Represents the current state of a penetration test engagement.
/// Used as input to the rule engine to determine which attack vectors apply.
/// </summary>
public record AttackState(
    string CurrentPhase,            // e.g., "no_creds", "user_found", "admin_access"
    List<string> AcquiredItems,     // What you've obtained (e.g., ["username", "hash"])
    List<int> OpenPorts,            // Discovered open ports
    List<string> Services,          // Detected services (e.g., ["smb", "http"])
    string? TargetOS                // Operating system if known
);
