namespace R2R.Core.Domain;

/// <summary>
/// Represents a service-based rule set loaded from JSON.
/// Maps to a specific network service (e.g., SMB, HTTP, SSH).
/// </summary>
public record ServiceRuleSet(
    string Service,                  // e.g., "SMB", "HTTP", "DNS"
    string Description,              // Service description
    List<int> Ports,                 // Ports this service uses
    List<string> ServiceNames,       // Service names from nmap
    List<string> TargetOs,           // Applicable OS ("Any", "Windows", "Linux")
    List<AttackVector> Vectors       // Attack vectors for this service
);
