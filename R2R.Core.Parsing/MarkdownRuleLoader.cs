using System.Text.RegularExpressions;
using Markdig;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using R2R.Core.Domain;

namespace R2R.Core.Parsing;

/// <summary>
/// Parses markdown files containing attack path information into structured RuleSet objects.
/// Designed to parse files like no_creds.md with sections for attack vectors.
/// </summary>
public class MarkdownRuleLoader
{
    private static readonly Regex ToolExtractor = new(@"^([a-zA-Z0-9\-_\.]+)", RegexOptions.Compiled);

    /// <summary>
    /// Loads a markdown file and parses it into a RuleSet.
    /// </summary>
    public static RuleSet LoadFromFile(string filePath)
    {
        var content = File.ReadAllText(filePath);
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        return ParseMarkdown(fileName, content);
    }

    /// <summary>
    /// Parses markdown content into a RuleSet.
    /// </summary>
    public static RuleSet ParseMarkdown(string id, string markdownContent)
    {
        var document = Markdown.Parse(markdownContent);
        var vectors = new List<AttackVector>();
        
        // Extract the main title (H1) and look for @phase: tag
        var h1Block = document.Descendants<HeadingBlock>().FirstOrDefault(h => h.Level == 1);
        var mainTitle = h1Block?.Inline?.FirstChild?.ToString() ?? id;
        
        // Extract phase from title if present (e.g., "# Title @phase:reconnaissance@")
        var phase = ExtractPhaseFromTitle(mainTitle);
        if (phase != null)
        {
            // Remove the phase tag from the display title
            mainTitle = System.Text.RegularExpressions.Regex.Replace(mainTitle, @"\s*@phase:[^@]+@\s*", "").Trim();
        }
        else
        {
            // Default phase mapping based on filename
            phase = MapFilenameToPhase(id);
        }

        var initialState = id.Replace("_", "").ToLowerInvariant();

        // Process each H2 section as an attack vector
        var headings = document.Descendants<HeadingBlock>()
            .Where(h => h.Level == 2)
            .ToList();

        foreach (var heading in headings)
        {
            // Use phase as prerequisite so it matches the current phase in RuleEngine
            var vector = ParseAttackVector(heading, phase);
            if (vector != null)
                vectors.Add(vector);
        }

        return new RuleSet(id, mainTitle, initialState, phase, vectors);
    }

    /// <summary>
    /// Extracts phase tag from markdown title (e.g., "@phase:reconnaissance@")
    /// </summary>
    private static string? ExtractPhaseFromTitle(string title)
    {
        var match = System.Text.RegularExpressions.Regex.Match(title, @"@phase:([^@]+)@");
        return match.Success ? match.Groups[1].Value.Trim().ToLowerInvariant() : null;
    }

    /// <summary>
    /// Maps filename to default phase if no explicit phase tag is found
    /// </summary>
    private static string MapFilenameToPhase(string filename)
    {
        return filename.ToLowerInvariant() switch
        {
            "no_creds" => "reconnaissance",
            "low_hanging" => "always",
            "mitm" => "initial_access",
            "valid_user" => "credential_access",
            "crack_hash" => "credential_access",
            "authenticated" => "lateral_movement",
            "lat_move" => "lateral_movement",
            "low_access" => "lateral_movement",
            "delegation" => "privilege_escalation",
            "acl" => "privilege_escalation",
            "adcs" => "privilege_escalation",
            "sccm" => "privilege_escalation",
            "know_vuln_auth" => "privilege_escalation",
            "admin" => "domain_admin",
            "dom_admin" => "domain_admin",
            "trusts" => "domain_admin",
            "persistence" => "persistence",
            _ => "reconnaissance" // Default to earliest phase
        };
    }

    private static AttackVector? ParseAttackVector(HeadingBlock heading, string prerequisite)
    {
        // Extract heading text and outcomes
        var headingText = ExtractHeadingText(heading);
        if (string.IsNullOrWhiteSpace(headingText))
            return null;

        var parts = headingText.Split(">>>", StringSplitOptions.TrimEntries);
        var vectorName = parts[0].Trim();
        var outcomes = parts.Skip(1)
            .Select(o => new Outcome(
                StateId: ToStateId(o),
                DisplayName: o,
                Description: null
            ))
            .ToList();

        // Extract commands from bullet lists following this heading
        var commands = ExtractCommandsAfterHeading(heading);

        var vectorId = ToStateId(vectorName);

        return new AttackVector(
            Id: vectorId,
            Name: vectorName,
            Prerequisites: new List<string> { prerequisite },
            PossibleOutcomes: outcomes,
            Commands: commands
        );
    }

    private static string ExtractHeadingText(HeadingBlock heading)
    {
        if (heading.Inline == null)
            return string.Empty;

        var text = new System.Text.StringBuilder();
        foreach (var inline in heading.Inline.Descendants())
        {
            if (inline is LiteralInline literal)
                text.Append(literal.Content.ToString());
            else if (inline is CodeInline code)
                text.Append(code.Content);
        }
        return text.ToString();
    }

    private static List<Command> ExtractCommandsAfterHeading(HeadingBlock heading)
    {
        var commands = new List<Command>();
        var nextBlock = GetNextSibling(heading);

        while (nextBlock != null && nextBlock is not HeadingBlock)
        {
            if (nextBlock is ListBlock listBlock)
            {
                foreach (var listItem in listBlock.Descendants<ListItemBlock>())
                {
                    var command = ExtractCommandFromListItem(listItem);
                    if (command != null)
                        commands.Add(command);
                }
            }
            nextBlock = GetNextSibling(nextBlock);
        }

        return commands;
    }

    private static Command? ExtractCommandFromListItem(ListItemBlock listItem)
    {
        var text = new System.Text.StringBuilder();
        
        foreach (var descendant in listItem.Descendants())
        {
            if (descendant is LiteralInline literal)
                text.Append(literal.Content.ToString());
            else if (descendant is CodeInline code)
                text.Append(code.Content);
        }

        var commandText = text.ToString().Trim();
        if (string.IsNullOrWhiteSpace(commandText))
            return null;

        // Try to extract tool name from the command
        var toolMatch = ToolExtractor.Match(commandText);
        var tool = toolMatch.Success ? toolMatch.Groups[1].Value : "unknown";

        return new Command(tool, commandText, null);
    }

    private static Block? GetNextSibling(Block block)
    {
        var parent = block.Parent;
        if (parent == null)
            return null;

        var siblings = parent is ContainerBlock container ? container.ToList() : new List<Block>();
        var index = siblings.IndexOf(block);
        
        if (index >= 0 && index < siblings.Count - 1)
            return siblings[index + 1];

        return null;
    }

    private static string ToStateId(string displayName)
    {
        // Convert "Scan network" -> "scan_network"
        return displayName
            .ToLowerInvariant()
            .Replace(" ", "_")
            .Replace("-", "_")
            .Trim();
    }
}
