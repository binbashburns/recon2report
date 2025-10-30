using System.Text.RegularExpressions;
using R2R.Core.Domain;
using R2R.Core.Parsing;
using R2R.Core.Rules;

// Bootstraps the minimal API host and exposes Swagger for interactive testing.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Load rule sets at startup
var ruleSets = new List<RuleSet>();
var docsPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "docs");
Console.WriteLine($"Looking for attack path files in: {docsPath}");

if (Directory.Exists(docsPath))
{
    // Load all markdown files from docs directory
    var markdownFiles = Directory.GetFiles(docsPath, "*.md", SearchOption.TopDirectoryOnly).ToList();
    
    Console.WriteLine($"Found {markdownFiles.Count} attack path file(s)");
    
    foreach (var mdFile in markdownFiles)
    {
        try
        {
            var ruleSet = MarkdownRuleLoader.LoadFromFile(mdFile);
            ruleSets.Add(ruleSet);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  ✓ {Path.GetFileName(mdFile)}: {ruleSet.Name} - Phase: {ruleSet.Phase} ({ruleSet.Vectors.Count} vectors)");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  ✗ {Path.GetFileName(mdFile)}: {ex.Message}");
            Console.ResetColor();
        }
    }
    
    if (!ruleSets.Any())
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("No attack path files loaded. Add .md files to /docs directory.");
        Console.ResetColor();
    }
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"Docs directory not found at: {docsPath}");
    Console.ResetColor();
}

var ruleEngine = new RuleEngine(ruleSets);
Console.WriteLine($"Rule engine initialized with {ruleSets.Count} ruleset(s)\n");

// Enable Swagger UI
app.UseSwagger();
app.UseSwaggerUI();

// Ephemeral store backing the API; data is lost once the process stops.
var db = new InMemoryDb();

// ---- In-memory CRUD ----
// Session endpoints track a single pentest/assessment run and are managed in memory.
app.MapPost("/sessions", (Session s) =>
{
    var id = Guid.NewGuid().ToString("n");
    s = s with { Id = id };
    db.Sessions[id] = s;
    return Results.Created($"/sessions/{id}", s);
});

// Quick fetch for session metadata by identifier.
app.MapGet("/sessions/{id}", (string id) =>
    db.Sessions.TryGetValue(id, out var s) ? Results.Ok(s) : Results.NotFound());

// Allows the UI to discard an entire engagement quickly.
app.MapDelete("/sessions/{id}", (string id) => db.Sessions.Remove(id) ? Results.NoContent() : Results.NotFound());

// Target endpoints associate discovered hosts/services with a session.
app.MapPost("/targets", (Target t) =>
{
    if (!db.Sessions.ContainsKey(t.SessionId)) return Results.BadRequest("Session not found");
    if (!IpValidator.IsValid(t.Ip)) return Results.BadRequest("Invalid IP address. Please provide a valid IP address (e.g., 192.168.1.1) or IP with CIDR notation (e.g., 192.168.1.0/24)");
    var id = Guid.NewGuid().ToString("n");
    t = t with { Id = id };
    db.Targets[id] = t;
    return Results.Created($"/targets/{id}", t);
});

// Fetches target metadata for the recon report or UI.
app.MapGet("/targets/{id}", (string id) =>
    db.Targets.TryGetValue(id, out var t) ? Results.Ok(t) : Results.NotFound());

// Keeps target details in sync after new evidence comes in.
app.MapPut("/targets/{id}", (string id, Target t) =>
{
    if (!db.Targets.ContainsKey(id)) return Results.NotFound();
    if (!db.Sessions.ContainsKey(t.SessionId)) return Results.BadRequest("Session not found");
    if (!IpValidator.IsValid(t.Ip)) return Results.BadRequest("Invalid IP address. Please provide a valid IP address (e.g., 192.168.1.1) or IP with CIDR notation (e.g., 192.168.1.0/24)");
    db.Targets[id] = t with { Id = id };
    return Results.Ok(db.Targets[id]);
});

// Clean up a target when it is no longer relevant to the engagement.
app.MapDelete("/targets/{id}", (string id) => db.Targets.Remove(id) ? Results.NoContent() : Results.NotFound());

// ---- Scan Results Management ----
// Upload and store parsed Nmap scan results for a target
app.MapPost("/targets/{id}/scan", (string id, ParseRequest req) => {
    if (!db.Targets.TryGetValue(id, out var target)) return Results.NotFound();
    var parseResult = NmapParser.ParseFull(req.NmapOutput ?? "");
    db.Targets[id] = target with { Ports = parseResult.Ports };
    
    return Results.Ok(new { 
        TargetId = id, 
        PortsDetected = parseResult.Ports.Count, 
        Ports = parseResult.Ports,
        DiscoveredInfo = new {
            parseResult.DomainName,
            parseResult.ComputerName,
            parseResult.FQDN,
            parseResult.DetectedOS
        }
    });
});

// Retrieve stored scan results for a target
app.MapGet("/targets/{id}/scan", (string id) => {
    if (!db.Targets.TryGetValue(id, out var target)) return Results.NotFound();
    if (target.Ports == null || !target.Ports.Any()) 
        return Results.Ok(new { Message = "No scan results uploaded yet", Ports = new List<OpenPort>() });
    return Results.Ok(new { TargetId = id, PortsDetected = target.Ports.Count, Ports = target.Ports });
});

// ---- Helper: Suggest Nmap commands (with explanations) ----
// Generates a curated list of scan commands based on IP/OS selections.
app.MapPost("/nmap/suggest", (SuggestRequest req) => {
    var cmds = NmapCommandBuilder.Build(req.Ip, req.Os);
    return Results.Ok(cmds);
});

// ---- Helper: Parse pasted Nmap normal output ----
// Converts raw Nmap output into structured `OpenPort` records.
// Note: This is stateless. Use POST /targets/{id}/scan to save results.
app.MapPost("/nmap/parse", (ParseRequest req) => {
    var parsed = NmapParser.Parse(req.NmapOutput ?? "");
    return Results.Ok(parsed);
});

// ---- Rule Engine: Suggest attack paths based on current state ----
// Uses loaded markdown rule sets to suggest applicable attack vectors
app.MapPost("/attack-paths/suggest", (AttackPathRequest req) => {
    var state = new AttackState(
        CurrentPhase: req.CurrentPhase ?? "reconnaissance",
        AcquiredItems: req.AcquiredItems ?? new List<string>(),
        OpenPorts: req.OpenPorts ?? new List<int>(),
        Services: req.Services ?? new List<string>(),
        TargetOS: req.TargetOS
    );

    // Get all applicable vectors for current phase (includes "always" phase)
    var allVectors = ruleEngine.Evaluate(state).ToList();

    return Results.Ok(new {
        CurrentPhase = req.CurrentPhase ?? "reconnaissance",
        TargetContext = new {
            TargetIp = req.TargetIp,
            DomainName = req.DomainName,
            IpRange = req.IpRange
        },
        ApplicableVectors = allVectors.Select(v => new {
            v.Id,
            v.Name,
            v.Prerequisites,
            PossibleOutcomes = v.PossibleOutcomes.Select(o => o.DisplayName).ToList(),
            Commands = v.Commands.Select(c => new { 
                c.Tool, 
                RawSyntax = c.Syntax,
                // Substitute variables in command syntax
                ReadyCommand = SubstituteVariables(c.Syntax, req.TargetIp, req.DomainName, req.IpRange)
            }).ToList()
        }).ToList()
    });
});

// Get ALL vectors for a phase (no prerequisite filtering) - for reference/cheatsheet mode
app.MapGet("/attack-paths/phase/{phase}", (string phase) => {
    var state = new AttackState(
        CurrentPhase: phase,
        AcquiredItems: new List<string>(),
        OpenPorts: new List<int>(),
        Services: new List<string>(),
        TargetOS: null // Don't filter by OS for raw output
    );
    
    // Get matching rulesets without prerequisite filtering
    var matchingRuleSets = ruleEngine.GetRuleSetsForPhase(phase);
    var allVectors = matchingRuleSets.SelectMany(rs => rs.Vectors).ToList();
    
    return Results.Ok(new {
        Phase = phase,
        TotalVectors = allVectors.Count,
        Vectors = allVectors.Select(v => new {
            v.Id,
            v.Name,
            v.Prerequisites,
            PossibleOutcomes = v.PossibleOutcomes.Select(o => o.DisplayName).ToList(),
            Commands = v.Commands.Select(c => new { 
                c.Tool, 
                RawSyntax = c.Syntax
            }).ToList()
        }).ToList()
    });
});

// Debug endpoint to see what's being filtered
app.MapGet("/debug/vectors", () => {
    return Results.Ok(new {
        TotalRuleSets = ruleSets.Count,
        RuleSets = ruleSets.Select(rs => new {
            rs.Id,
            rs.Name,
            rs.Phase,
            VectorCount = rs.Vectors.Count,
            Vectors = rs.Vectors.Select(v => new {
                v.Name,
                v.Prerequisites,
                CommandCount = v.Commands.Count
            }).ToList()
        }).ToList()
    });
});

// Helper function to substitute common variables in command templates
static string SubstituteVariables(string template, string? targetIp, string? domain, string? ipRange)
{
    var result = template;
    
    // Substitute variables (case-insensitive)
    if (!string.IsNullOrWhiteSpace(targetIp))
    {
        result = Regex.Replace(result, @"<ip>|<dc_ip>|<target>", targetIp, RegexOptions.IgnoreCase);
    }
    
    if (!string.IsNullOrWhiteSpace(domain))
    {
        result = Regex.Replace(result, @"<domain>|<domain_name>", domain, RegexOptions.IgnoreCase);
    }
    
    if (!string.IsNullOrWhiteSpace(ipRange))
    {
        result = Regex.Replace(result, @"<ip_range>", ipRange, RegexOptions.IgnoreCase);
    }
    
    return result;
}

// Activates the ASP.NET Core request pipeline.
app.Run();

// Request DTOs exposed to the front-end for helper endpoints.
public record SuggestRequest(string Ip, string Os); // Os: "Windows"|"Linux"
public record ParseRequest(string? NmapOutput);
public record AttackPathRequest(
    string? CurrentPhase,       // e.g., "no_creds", "user_found"
    List<string>? AcquiredItems, // e.g., ["username", "hash"]
    List<int>? OpenPorts,        // e.g., [445, 139, 88]
    List<string>? Services,      // e.g., ["smb", "ldap"]
    string? TargetOS,            // e.g., "Windows", "Linux"
    string? TargetIp,            // Target IP for variable substitution
    string? DomainName,          // Domain name for variable substitution
    string? IpRange              // IP range for variable substitution
);
public record Session(string Id, string Name);
public record Target(string Id, string SessionId, string Ip, string Os, List<OpenPort>? Ports = null);

// Tiny persistence wrapper so endpoints can share mutable state.
class InMemoryDb {
    public Dictionary<string, Session> Sessions { get; } = new();
    public Dictionary<string, Target>  Targets  { get; } = new();
}

// --------- Helpers (Phase 1 general guidance) ----------
// Central location for curated recon building blocks surfaced to the client.
public static class NmapCommandBuilder {
    public static IEnumerable<NmapCommand> Build(string ip, string os)
    {
        // Quick discovery scan
        yield return new("Quick Scan (Top 100 ports)",
            $"nmap --top-ports 100 -oN nmap_quick.txt {ip}",
            "Fast discovery (~30 seconds). Great for initial enumeration of most common services.");

        // Standard recommended scan
        yield return new("Standard Scan (Recommended)",
            $"nmap -sV -sC -oN nmap_standard.txt {ip}",
            "Top 1000 ports with version detection and default scripts (~2-5 minutes). Best starting point.");

        // Full TCP scan (with better settings)
        var fullScanPrefix = os.Equals("Windows", StringComparison.OrdinalIgnoreCase) ? "" : "sudo ";
        yield return new("Full TCP Scan",
            $"{fullScanPrefix}nmap -sS -p- --min-rate 5000 -T4 -oN nmap_all_ports.txt {ip}",
            "Comprehensive scan of all 65,535 TCP ports (~20-40 minutes). Use sudo for faster SYN scan on Linux.");

        // UDP scan
        yield return new("Top UDP Ports",
            $"sudo nmap -sU --top-ports 100 -oN nmap_udp.txt {ip}",
            "UDP is slower; scan top 100 ports for DNS/SNMP/DHCP/NTP (~5-10 minutes).");

        // OS-specific post-scan enumeration notes
        if (os.Equals("Windows", StringComparison.OrdinalIgnoreCase)) {
            yield return new("Windows Enumeration Tips", "N/A",
                "After scan: Check SMB (445) with smbclient/enum4linux, RDP (3389) cipher strength, WinRM (5985/5986).");
        } else {
            yield return new("Linux Enumeration Tips", "N/A",
                "After scan: Run ssh-audit on port 22, gobuster on web ports, check for NFS (2049), exploit-db searches.");
        }
    }
}
// Shape of the helper data surfaced in the `/nmap/suggest` response.
public record NmapCommand(string Title, string Command, string Explanation);
public record OpenPort(int Number, string Protocol, string? Service, string? Version);

// Turns unstructured Nmap text into strongly typed port data.
public static class NmapParser {
    // Parses typical "PORT   STATE SERVICE VERSION" lines from nmap normal output
    static readonly Regex PortLine = new(@"^(?<port>\d{1,5})\/(?<proto>tcp|udp)\s+(?<state>open|filtered|closed)\s+(?<service>\S+)(\s+(?<version>.+))?$",
                                         RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static List<OpenPort> Parse(string output)
    {
        return ParseFull(output).Ports;
    }
    
    public static NmapParseResult ParseFull(string output)
    {
        var ports = new List<OpenPort>();
        string? domainName = null;
        string? computerName = null;
        string? fqdn = null;
        string? detectedOS = null;

        foreach (var raw in output.Split('\n')) {
            var line = raw.Trim();
            
            // Parse port lines
            var m = PortLine.Match(line);
            if (m.Success) {
                if (!int.TryParse(m.Groups["port"].Value, out var port) || port < 1 || port > 65535) continue;
                var proto   = m.Groups["proto"].Value;
                var state   = m.Groups["state"].Value;
                if (!string.Equals(state, "open", StringComparison.OrdinalIgnoreCase)) continue;
                var service = m.Groups["service"].Value;
                var version = m.Groups["version"].Success ? m.Groups["version"].Value.Trim() : null;
                ports.Add(new OpenPort(port, proto, string.IsNullOrWhiteSpace(service) ? null : service, version));
                continue;
            }
            
            // Extract domain info from smb-os-discovery
            if (line.Contains("Domain name:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                    domainName = parts[1].Trim();
            }
            
            if (line.Contains("Computer name:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                    computerName = parts[1].Trim();
            }
            
            if (line.Contains("FQDN:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                    fqdn = parts[1].Trim();
            }
            
            if (line.Contains("|   OS:", StringComparison.OrdinalIgnoreCase))
            {
                var parts = line.Split(':', 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                    detectedOS = parts[1].Trim();
            }
        }
        
        // Dedupe ports
        var uniquePorts = ports
            .GroupBy(p => (p.Number, p.Protocol.ToLowerInvariant()))
            .Select(g => g.First())
            .OrderBy(p => p.Number)
            .ToList();

        return new NmapParseResult(uniquePorts, domainName, computerName, fqdn, detectedOS);
    }
}

public record NmapParseResult(List<OpenPort> Ports, string? DomainName, string? ComputerName, string? FQDN, string? DetectedOS);

// Validates IP addresses and CIDR notation to prevent invalid input.
public static class IpValidator
{
    private static readonly Regex IpAddressPattern = new(
        @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/(?:[0-9]|[12][0-9]|3[0-2]))?$",
        RegexOptions.Compiled);

    public static bool IsValid(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return false;
        return IpAddressPattern.IsMatch(ip.Trim());
    }
}
