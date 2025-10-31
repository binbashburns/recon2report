using R2R.Core.Domain;

namespace R2R.Core.Rules;

/// <summary>
/// Simplified rule engine that loads service-based attack vectors.
/// Filters vectors based on detected open ports/services and current phase.
/// </summary>
public class ServiceRuleEngine
{
    private readonly List<ServiceRuleSet> _serviceRuleSets;

    public ServiceRuleEngine(List<ServiceRuleSet> serviceRuleSets)
    {
        _serviceRuleSets = serviceRuleSets ?? new List<ServiceRuleSet>();
    }

    /// <summary>
    /// Evaluates attack state and returns applicable vectors.
    /// Only loads vectors from services that have open ports.
    /// </summary>
    public List<AttackVector> Evaluate(AttackState state)
    {
        var applicableVectors = new List<AttackVector>();

        // Get the current phase
        var currentPhase = DeterminePhaseFromState(state);

        // Find service rule sets that match the detected ports/services
        var relevantServices = GetRelevantServices(state);

        foreach (var serviceRuleSet in relevantServices)
        {
            // Filter vectors by phase and prerequisites
            foreach (var vector in serviceRuleSet.Vectors)
            {
                // Check if vector is for current or "always" phase
                var vectorPhase = vector.Prerequisites.FirstOrDefault() ?? currentPhase;
                
                if (IsVectorApplicable(vector, state, currentPhase) && 
                    IsOsCompatible(serviceRuleSet.TargetOs, state.TargetOS))
                {
                    applicableVectors.Add(vector);
                }
            }
        }

        return applicableVectors;
    }

    /// <summary>
    /// Gets service rule sets that match the open ports/services in the attack state.
    /// Always includes "Network General" service.
    /// </summary>
    private List<ServiceRuleSet> GetRelevantServices(AttackState state)
    {
        var relevant = new List<ServiceRuleSet>();

        foreach (var serviceRuleSet in _serviceRuleSets)
        {
            // Always include network-general attacks (no specific port requirement)
            if (!serviceRuleSet.Ports.Any())
            {
                relevant.Add(serviceRuleSet);
                continue;
            }

            // Include if any of the service's ports are open
            if (serviceRuleSet.Ports.Any(p => state.OpenPorts.Contains(p)))
            {
                relevant.Add(serviceRuleSet);
                continue;
            }

            // Include if any of the service's service names match detected services
            if (serviceRuleSet.ServiceNames.Any(sn => 
                state.Services.Any(s => s.Equals(sn, StringComparison.OrdinalIgnoreCase))))
            {
                relevant.Add(serviceRuleSet);
            }
        }

        return relevant;
    }

    /// <summary>
    /// Determines if a vector is applicable based on phase and prerequisites.
    /// </summary>
    private bool IsVectorApplicable(AttackVector vector, AttackState state, string currentPhase)
    {
        // Get the vector's phase from prerequisites or default to reconnaissance
        var vectorPhase = "reconnaissance";
        
        // Check common phase keywords in prerequisites
        var phaseKeywords = new[] { "reconnaissance", "credential_access", "lateral_movement", 
                                    "privilege_escalation", "persistence" };
        
        foreach (var prereq in vector.Prerequisites)
        {
            if (phaseKeywords.Contains(prereq.ToLowerInvariant()))
            {
                vectorPhase = prereq.ToLowerInvariant();
                break;
            }
        }

        // Allow if vector is for current phase
        if (vectorPhase.Equals(currentPhase, StringComparison.OrdinalIgnoreCase))
        {
            // Check if other prerequisites are met
            return CheckPrerequisites(vector.Prerequisites, state);
        }

        return false;
    }

    /// <summary>
    /// Checks if non-phase prerequisites are met.
    /// </summary>
    private bool CheckPrerequisites(List<string> prerequisites, AttackState state)
    {
        if (!prerequisites.Any())
            return true;

        // Phase keywords don't count as prerequisites
        var phaseKeywords = new[] { "reconnaissance", "credential_access", "lateral_movement", 
                                    "privilege_escalation", "persistence" };
        
        var nonPhasePrereqs = prerequisites
            .Where(p => !phaseKeywords.Contains(p.ToLowerInvariant()))
            .ToList();

        if (!nonPhasePrereqs.Any())
            return true;

        // Check if any required prerequisite is met
        foreach (var prereq in nonPhasePrereqs)
        {
            if (state.AcquiredItems.Any(item => item.Equals(prereq, StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Checks if service is compatible with target OS.
    /// </summary>
    private bool IsOsCompatible(List<string> targetOsList, string? targetOs)
    {
        if (!targetOsList.Any() || targetOsList.Contains("Any"))
            return true;

        if (string.IsNullOrWhiteSpace(targetOs))
            return true;

        return targetOsList.Any(os => targetOs.Contains(os, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Determines the appropriate phase based on the current attack state.
    /// </summary>
    private string DeterminePhaseFromState(AttackState state)
    {
        var phase = state.CurrentPhase?.ToLowerInvariant() ?? "";

        return phase switch
        {
            "no_creds" or "nocreds" or "reconnaissance" or "initial_access" => "reconnaissance",
            "valid_user" or "validuser" or "credential_access" => "credential_access",
            "authenticated" or "authenticated_user" or "lateral_movement" => "lateral_movement",
            "privilege_escalation" or "privesc" => "privilege_escalation",
            "admin" or "domain_admin" or "domainadmin" => "domain_admin",
            "persistence" => "persistence",
            _ => "reconnaissance"
        };
    }

    /// <summary>
    /// Gets all vectors for a specific phase (for reference/cheatsheet mode).
    /// </summary>
    public List<AttackVector> GetVectorsForPhase(string phase)
    {
        var normalizedPhase = DeterminePhaseFromState(new AttackState(phase, new(), new(), new(), null));
        var allVectors = new List<AttackVector>();

        foreach (var serviceRuleSet in _serviceRuleSets)
        {
            foreach (var vector in serviceRuleSet.Vectors)
            {
                // Check if vector belongs to this phase
                var vectorPhase = vector.Prerequisites.FirstOrDefault() ?? "reconnaissance";
                if (vectorPhase.Equals(normalizedPhase, StringComparison.OrdinalIgnoreCase))
                {
                    allVectors.Add(vector);
                }
            }
        }

        return allVectors;
    }

    /// <summary>
    /// Gets all service rule sets (for debugging/info).
    /// </summary>
    public List<ServiceRuleSet> GetAllServices() => _serviceRuleSets;
}
