using R2R.Core.Domain;

namespace R2R.Core.Rules;

/// <summary>
/// Evaluates the current attack state against loaded rule sets to suggest next attack vectors.
/// </summary>
public class RuleEngine
{
    private readonly List<RuleSet> _ruleSets;

    public RuleEngine(List<RuleSet> ruleSets)
    {
        _ruleSets = ruleSets ?? new List<RuleSet>();
    }

    /// <summary>
    /// Evaluates the current state and returns applicable attack vectors based on phase.
    /// Includes vectors from the current phase AND "always" phase.
    /// Only returns vectors whose prerequisites are met and match the target OS.
    /// </summary>
    public List<AttackVector> Evaluate(AttackState state)
    {
        var applicableVectors = new List<AttackVector>();

        // Get the current phase from state (defaults to reconnaissance if not set)
        var currentPhase = DeterminePhaseFromState(state);

        // Find rule sets that match the current phase OR are marked as "always"
        var matchingRuleSets = _ruleSets
            .Where(rs => rs.Phase.Equals(currentPhase, StringComparison.OrdinalIgnoreCase) ||
                        rs.Phase.Equals("always", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var ruleSet in matchingRuleSets)
        {
            // Filter vectors by prerequisites and OS
            foreach (var vector in ruleSet.Vectors)
            {
                if (IsVectorApplicable(vector, state) && IsOsCompatible(vector, state.TargetOS))
                {
                    applicableVectors.Add(vector);
                }
            }
        }

        return applicableVectors;
    }

    /// <summary>
    /// Gets all rule sets for a specific phase (no filtering).
    /// Used for raw output/cheatsheet mode.
    /// </summary>
    public List<RuleSet> GetRuleSetsForPhase(string phase)
    {
        var normalizedPhase = DeterminePhaseFromState(new AttackState(phase, new(), new(), new(), null));
        
        return _ruleSets
            .Where(rs => rs.Phase.Equals(normalizedPhase, StringComparison.OrdinalIgnoreCase) ||
                        rs.Phase.Equals("always", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>
    /// Determines the appropriate phase based on the current attack state.
    /// This maps the old "CurrentPhase" string to the new phase system.
    /// </summary>
    private string DeterminePhaseFromState(AttackState state)
    {
        // Check for explicit phase in CurrentPhase
        var phase = state.CurrentPhase?.ToLowerInvariant() ?? "";

        // Map old state names to new phases
        return phase switch
        {
            "no_creds" or "nocreds" or "reconnaissance" or "initial_access" => "reconnaissance",
            "valid_user" or "validuser" or "credential_access" => "credential_access",
            "authenticated" or "authenticated_user" or "lateral_movement" => "lateral_movement",
            "privilege_escalation" or "privesc" => "privilege_escalation",
            "admin" or "domain_admin" or "domainadmin" => "domain_admin",
            "persistence" => "persistence",
            _ => "reconnaissance" // Default to reconnaissance
        };
    }

    /// <summary>
    /// Determines if an attack vector is applicable given the current state.
    /// </summary>
    private bool IsVectorApplicable(AttackVector vector, AttackState state)
    {
        // If no prerequisites, it's always applicable in its phase
        if (!vector.Prerequisites.Any())
            return true;

        // Check if prerequisites are met
        foreach (var prereq in vector.Prerequisites)
        {
            // If the prerequisite matches the current phase, it's applicable
            if (prereq.Equals(state.CurrentPhase, StringComparison.OrdinalIgnoreCase))
                return true;

            // Or if we have acquired the prerequisite item
            if (state.AcquiredItems.Any(item => item.Equals(prereq, StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        // Additional filtering based on ports/services could be added here
        // For now, we rely on prerequisites matching the phase

        return false;
    }

    /// <summary>
    /// Determines if an attack vector is compatible with the target OS.
    /// Filters out Windows-specific attacks for Linux targets and vice versa.
    /// No filtering during reconnaissance/initial_access - OS discovery happens here.
    /// </summary>
    private bool IsOsCompatible(AttackVector vector, string? targetOs)
    {
        if (string.IsNullOrWhiteSpace(targetOs))
            return true; // If OS unknown, show everything

        var os = targetOs.ToLowerInvariant();
        
        // Don't filter during reconnaissance - we're still discovering the OS
        // This allows initial scanning, enumeration, and poisoning attacks
        var vectorName = vector.Name.ToLowerInvariant();
        var isReconVector = vectorName.Contains("scan") || 
                           vectorName.Contains("enumerate") || 
                           vectorName.Contains("poison") ||
                           vectorName.Contains("discover") ||
                           vectorName.Contains("find");
        
        if (isReconVector)
            return true;

        var vectorCommands = string.Join(" ", vector.Commands.Select(c => c.Syntax.ToLowerInvariant()));

        // Windows-only keywords (Active Directory specific that truly only work on Windows)
        var windowsOnlyKeywords = new[] { "mimikatz", "rubeus", "powershell.exe", 
                                          "psexec", "wmi", "dcom", "gpo" };
        
        // Linux-only keywords
        var linuxOnlyKeywords = new[] { "sudo", "/etc/passwd", "/etc/shadow", "cron" };

        // If target is Linux, filter out Windows-only attacks
        if (os.Contains("linux") || os.Contains("unix"))
        {
            foreach (var keyword in windowsOnlyKeywords)
            {
                if (vectorName.Contains(keyword) || vectorCommands.Contains(keyword))
                    return false;
            }
        }

        // If target is Windows, filter out Linux-only attacks
        if (os.Contains("windows") || os.Contains("win"))
        {
            foreach (var keyword in linuxOnlyKeywords)
            {
                if (vectorName.Contains(keyword) || vectorCommands.Contains(keyword))
                    return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Gets all attack vectors that match specific services or ports.
    /// Only searches within the current phase and "always" phase (not future phases).
    /// Useful for finding low-hanging fruit and service-specific attacks.
    /// </summary>
    public List<AttackVector> GetVectorsForServices(AttackState state, List<string> services)
    {
        var currentPhase = DeterminePhaseFromState(state);
        
        // Only search vectors from current phase and "always" phase
        var relevantVectors = _ruleSets
            .Where(rs => rs.Phase.Equals(currentPhase, StringComparison.OrdinalIgnoreCase) ||
                        rs.Phase.Equals("always", StringComparison.OrdinalIgnoreCase))
            .SelectMany(rs => rs.Vectors)
            .ToList();
        
        // Filter vectors that mention any of the services in their name or commands
        return relevantVectors
            .Where(v => services.Any(service => 
                v.Name.Contains(service, StringComparison.OrdinalIgnoreCase) ||
                v.Commands.Any(c => c.Syntax.Contains(service, StringComparison.OrdinalIgnoreCase))
            ))
            .ToList();
    }

    /// <summary>
    /// Gets all attack vectors that are relevant for specific ports.
    /// Only searches within the current phase and "always" phase (not future phases).
    /// </summary>
    public List<AttackVector> GetVectorsForPorts(AttackState state, List<int> ports)
    {
        // Common port-to-service mappings
        var serviceHints = new Dictionary<int, string>
        {
            { 445, "smb" }, { 139, "smb" },
            { 389, "ldap" }, { 636, "ldaps" },
            { 88, "kerberos" },
            { 53, "dns" },
            { 80, "http" }, { 443, "https" },
            { 8080, "http" }, { 8180, "tomcat" }, { 8009, "tomcat" }
        };

        var relevantServices = ports
            .Where(p => serviceHints.ContainsKey(p))
            .Select(p => serviceHints[p])
            .Distinct()
            .ToList();

        if (!relevantServices.Any())
            return new List<AttackVector>();

        return GetVectorsForServices(state, relevantServices);
    }
}
