using System.Text.Json;
using R2R.Core.Domain;

namespace R2R.Core.Parsing;

/// <summary>
/// Loads service-based attack vectors from JSON files.
/// Each JSON file represents a single service (e.g., SMB, HTTP) with its attack vectors.
/// </summary>
public class ServiceRuleLoader
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    /// <summary>
    /// Loads a service rule set from a JSON file.
    /// </summary>
    public static ServiceRuleSet LoadFromFile(string filePath)
    {
        var json = File.ReadAllText(filePath);
        return LoadFromJson(json);
    }

    /// <summary>
    /// Loads a service rule set from JSON content.
    /// </summary>
    public static ServiceRuleSet LoadFromJson(string json)
    {
        var dto = JsonSerializer.Deserialize<ServiceRuleSetDto>(json, JsonOptions);
        
        if (dto == null)
            throw new InvalidOperationException("Failed to deserialize service rule set");

        // Convert DTO to domain model
        var vectors = dto.Vectors?.Select(v => new AttackVector(
            Id: v.Id ?? "",
            Name: v.Name ?? "",
            Prerequisites: v.Prerequisites ?? new List<string>(),
            PossibleOutcomes: (v.Outcomes ?? new List<string>()).Select(o => new Outcome(
                StateId: o.ToLowerInvariant().Replace(" ", "_"),  // Convert "Domain Admin" to "domain_admin"
                DisplayName: o,                                    // Keep original display name
                Description: null                                  // No description from simple string
            )).ToList(),
            Commands: (v.Commands ?? new List<CommandDto>()).Select(c => new Command(
                Tool: c.Tool ?? "",
                Syntax: c.Syntax ?? "",
                Description: c.Description
            )).ToList()
        )).ToList() ?? new List<AttackVector>();

        return new ServiceRuleSet(
            Service: dto.Service ?? "",
            Description: dto.Description ?? "",
            Ports: dto.Ports ?? new List<int>(),
            ServiceNames: dto.ServiceNames ?? new List<string>(),
            TargetOs: dto.TargetOs ?? new List<string>(),
            Vectors: vectors
        );
    }

    /// <summary>
    /// Loads all service rule sets from a directory.
    /// </summary>
    public static List<ServiceRuleSet> LoadFromDirectory(string directoryPath)
    {
        var ruleSets = new List<ServiceRuleSet>();

        if (!Directory.Exists(directoryPath))
            return ruleSets;

        var jsonFiles = Directory.GetFiles(directoryPath, "*.json", SearchOption.AllDirectories);

        foreach (var file in jsonFiles)
        {
            try
            {
                var ruleSet = LoadFromFile(file);
                ruleSets.Add(ruleSet);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to load {Path.GetFileName(file)}: {ex.Message}");
            }
        }

        return ruleSets;
    }

    // DTOs for JSON deserialization
    private class ServiceRuleSetDto
    {
        public string? Service { get; set; }
        public string? Description { get; set; }
        public List<int>? Ports { get; set; }
        public List<string>? ServiceNames { get; set; }
        public List<string>? TargetOs { get; set; }
        public List<VectorDto>? Vectors { get; set; }
    }

    private class VectorDto
    {
        public string? Id { get; set; }
        public string? Name { get; set; }
        public string? Phase { get; set; }
        public List<string>? Prerequisites { get; set; }
        public string? Description { get; set; }
        public List<CommandDto>? Commands { get; set; }
        public List<string>? Outcomes { get; set; }
    }

    private class CommandDto
    {
        public string? Tool { get; set; }
        public string? Syntax { get; set; }
        public string? Description { get; set; }
    }
}
