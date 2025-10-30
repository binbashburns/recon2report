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
    /// Evaluates the current state and returns applicable attack vectors.
    /// </summary>
    public List<AttackVector> Evaluate(AttackState state)
    {
        var applicableVectors = new List<AttackVector>();

        // Find rule sets that match the current phase
        var matchingRuleSets = _ruleSets
            .Where(rs => rs.InitialState.Equals(state.CurrentPhase, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var ruleSet in matchingRuleSets)
        {
            foreach (var vector in ruleSet.Vectors)
            {
                if (IsVectorApplicable(vector, state))
                {
                    applicableVectors.Add(vector);
                }
            }
        }

        return applicableVectors;
    }

    /// <summary>
    /// Determines if an attack vector is applicable given the current state.
    /// </summary>
    private bool IsVectorApplicable(AttackVector vector, AttackState state)
    {
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
    /// Gets all attack vectors that match specific services or ports.
    /// Useful for filtering suggestions based on discovered services.
    /// </summary>
    public List<AttackVector> GetVectorsForServices(AttackState state, List<string> services)
    {
        var allVectors = Evaluate(state);
        
        // Filter vectors that mention any of the services in their name or commands
        return allVectors
            .Where(v => services.Any(service => 
                v.Name.Contains(service, StringComparison.OrdinalIgnoreCase) ||
                v.Commands.Any(c => c.Syntax.Contains(service, StringComparison.OrdinalIgnoreCase))
            ))
            .ToList();
    }

    /// <summary>
    /// Gets all attack vectors that are relevant for specific ports.
    /// </summary>
    public List<AttackVector> GetVectorsForPorts(AttackState state, List<int> ports)
    {
        var allVectors = Evaluate(state);
        
        // Common port-to-service mappings
        var serviceHints = new Dictionary<int, string>
        {
            { 445, "smb" }, { 139, "smb" },
            { 389, "ldap" }, { 636, "ldaps" },
            { 88, "kerberos" },
            { 53, "dns" },
            { 80, "http" }, { 443, "https" }
        };

        var relevantServices = ports
            .Where(p => serviceHints.ContainsKey(p))
            .Select(p => serviceHints[p])
            .Distinct()
            .ToList();

        if (!relevantServices.Any())
            return allVectors;

        return GetVectorsForServices(state, relevantServices);
    }
}
