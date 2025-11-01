using System.Text.RegularExpressions;
using System.Xml.Linq;
using R2R.Core.Domain;
using R2R.Core.Parsing;
using R2R.Core.Rules;
using R2R.Api;

// Bootstraps the minimal API host and exposes Swagger for interactive testing.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerDocumentation();

// Add CORS policy for frontend development
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:5173")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

// Load service-based rule sets at startup
var servicesPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "services");
Console.WriteLine($"Looking for service files in: {servicesPath}");

var serviceRuleSets = new List<ServiceRuleSet>();

if (Directory.Exists(servicesPath))
{
    serviceRuleSets = ServiceRuleLoader.LoadFromDirectory(servicesPath);
    Console.WriteLine($"Loaded {serviceRuleSets.Count} service rule set(s)");
    
    foreach (var svc in serviceRuleSets)
    {
        Console.ForegroundColor = ConsoleColor.Green;
        var portList = svc.Ports.Any() ? string.Join(",", svc.Ports) : "N/A";
        Console.WriteLine($"  ✓ {svc.Service}: {svc.Vectors.Count} vectors (Ports: {portList})");
        Console.ResetColor();
    }
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"Services directory not found at: {servicesPath}");
    Console.ResetColor();
}

var ruleEngine = new ServiceRuleEngine(serviceRuleSets);
Console.WriteLine($"\nRule engine initialized with {serviceRuleSets.Count} service(s)\n");

// Enable Swagger UI
app.UseSwagger();
app.UseSwaggerUI();

// Enable CORS
app.UseCors("AllowFrontend");

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
})
.WithSessionExamples();

// Quick fetch for session metadata by identifier.
app.MapGet("/sessions/{id}", (string id) =>
    db.Sessions.TryGetValue(id, out var s) ? Results.Ok(s) : Results.NotFound());

// Get all targets associated with a session
app.MapGet("/sessions/{id}/targets", (string id) => {
    if (!db.Sessions.ContainsKey(id)) return Results.NotFound();
    
    var sessionTargets = db.Targets.Values
        .Where(t => t.SessionId == id)
        .Select(t => new {
            t.Id,
            t.Ip,
            t.Os,
            PortCount = t.Ports?.Count ?? 0,
            HasPorts = t.Ports?.Any() == true
        })
        .ToList();
    
    return Results.Ok(new {
        SessionId = id,
        TargetCount = sessionTargets.Count,
        Targets = sessionTargets
    });
});

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
})
.WithTargetExamples();

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
// If multiple hosts are detected, creates a separate target for each
app.MapPost("/targets/{id}/scan", (string id, ParseRequest req) => {
    if (!db.Targets.TryGetValue(id, out var target)) return Results.NotFound();
    
    var hosts = NmapParser.ParseMultipleHosts(req.NmapOutput ?? "");
    
    // If multiple hosts found, create separate targets for each
    if (hosts.Count > 1)
    {
        var createdTargets = new List<object>();
        
        foreach (var host in hosts)
        {
            var newTargetId = Guid.NewGuid().ToString("n");
            var detectedOs = host.DetectedOS ?? target.Os; // Use detected OS or fall back to original
            
            var newTarget = new Target(
                Id: newTargetId,
                SessionId: target.SessionId,
                Ip: host.IpAddress,
                Os: detectedOs,
                Ports: host.Ports
            );
            
            db.Targets[newTargetId] = newTarget;
            
            createdTargets.Add(new {
                TargetId = newTargetId,
                IpAddress = host.IpAddress,
                Hostname = host.Hostname,
                PortsDetected = host.Ports.Count,
                Ports = host.Ports,
                DiscoveredInfo = new {
                    host.DomainName,
                    host.ComputerName,
                    host.FQDN,
                    DetectedOS = host.DetectedOS
                }
            });
        }
        
        return Results.Ok(new {
            Message = $"Multiple hosts detected. Created {hosts.Count} separate targets.",
            HostCount = hosts.Count,
            OriginalTargetId = id,
            DiscoveredTargets = createdTargets
        });
    }
    
    // Single host - update the existing target
    var singleHost = hosts.FirstOrDefault();
    if (singleHost != null)
    {
        var detectedOs = singleHost.DetectedOS ?? target.Os;
        db.Targets[id] = target with { 
            Ip = singleHost.IpAddress, 
            Os = detectedOs,
            Ports = singleHost.Ports 
        };
        
        return Results.Ok(new { 
            TargetId = id, 
            PortsDetected = singleHost.Ports.Count, 
            Ports = singleHost.Ports,
            DiscoveredInfo = new {
                singleHost.DomainName,
                singleHost.ComputerName,
                singleHost.FQDN,
                DetectedOS = singleHost.DetectedOS
            }
        });
    }
    
    return Results.BadRequest("No hosts found in scan output");
})
.WithScanUploadExamples();

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
})
.WithNmapSuggestExamples();

// ---- Rule Engine: Suggest attack paths based on current state ----
// Uses loaded service rule sets to suggest applicable attack vectors
app.MapPost("/attack-paths/suggest", (AttackPathRequest req) => {
    var state = new AttackState(
        CurrentPhase: req.CurrentPhase ?? "reconnaissance",
        AcquiredItems: req.AcquiredItems ?? new List<string>(),
        OpenPorts: req.OpenPorts ?? new List<int>(),
        Services: req.Services ?? new List<string>(),
        TargetOS: req.TargetOS
    );

    // Get all applicable vectors with their service names
    var allVectorsWithService = ruleEngine.EvaluateWithService(state).ToList();
    
    // Try to get IP range from session if not provided in request
    var ipRange = req.IpRange;
    if (string.IsNullOrWhiteSpace(ipRange) && !string.IsNullOrWhiteSpace(req.SessionId))
    {
        if (db.Sessions.TryGetValue(req.SessionId, out var session))
        {
            ipRange = session.IpRange;
        }
    }

    return Results.Ok(new {
        CurrentPhase = req.CurrentPhase ?? "reconnaissance",
        TargetContext = new {
            TargetIp = req.TargetIp,
            DomainName = req.DomainName,
            IpRange = ipRange
        },
        ApplicableVectors = allVectorsWithService.Select(vs => new {
            vs.Vector.Id,
            vs.Vector.Name,
            vs.Vector.Prerequisites,
            Service = vs.ServiceName,
            PossibleOutcomes = vs.Vector.PossibleOutcomes.Select(o => o.DisplayName).ToList(),
            Commands = vs.Vector.Commands.Select(c => new { 
                c.Tool, 
                RawSyntax = c.Syntax,
                // Substitute variables in command syntax, including open ports
                ReadyCommand = SubstituteVariables(c.Syntax, req.TargetIp, req.DomainName, ipRange, req.OpenPorts)
            }).ToList()
        }).ToList()
    });
})
.WithAttackPathSuggestExamples();

// ---- Rule Engine: Get all vectors for a phase (reference/dictionary mode) ----
// Returns all vectors for a given phase without filtering by ports/services
app.MapGet("/attack-paths/all", (string? phase) => {
    var currentPhase = phase?.ToLowerInvariant() ?? "reconnaissance";
    
    // Get all vectors for this phase from all services (no filtering)
    var allVectors = ruleEngine.GetAllVectorsForPhase(currentPhase);
    
    return Results.Ok(new {
        Phase = currentPhase,
        Vectors = allVectors.Select(vs => new {
            vs.Vector.Id,
            vs.Vector.Name,
            Description = GetVectorDescription(vs.Vector),
            vs.Vector.Prerequisites,
            Service = vs.ServiceName,
            PossibleOutcomes = vs.Vector.PossibleOutcomes.Select(o => o.DisplayName).ToList(),
            Commands = vs.Vector.Commands.Select(c => new {
                c.Tool,
                Syntax = c.Syntax, // Raw syntax with placeholders
                c.Description
            }).ToList()
        }).ToList()
    });
})
.WithAttackPathsAllExamples();

// Helper to get a description for a vector
string GetVectorDescription(AttackVector vector)
{
    // Check if any command has a description we can use
    var cmdDesc = vector.Commands.FirstOrDefault()?.Description;
    return cmdDesc ?? $"Attack vector for {vector.Name}";
}

// Get ALL vectors for a phase (no prerequisite filtering) - for reference/cheatsheet mode
app.MapGet("/attack-paths/phase/{phase}", (string phase) => {
    var allVectors = ruleEngine.GetVectorsForPhase(phase);
    
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

// Debug endpoint to see what services are loaded
app.MapGet("/debug/services", () => {
    var allServices = ruleEngine.GetAllServices();
    return Results.Ok(new {
        TotalServices = allServices.Count,
        Services = allServices.Select(svc => new {
            svc.Service,
            svc.Description,
            Ports = svc.Ports,
            ServiceNames = svc.ServiceNames,
            TargetOs = svc.TargetOs,
            VectorCount = svc.Vectors.Count,
            Vectors = svc.Vectors.Select(v => new {
                v.Name,
                v.Prerequisites,
                CommandCount = v.Commands.Count
            }).ToList()
        }).ToList()
    });
});

// Helper function to substitute common variables in command templates
static string SubstituteVariables(string template, string? targetIp, string? domain, string? ipRange, List<int>? openPorts = null)
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
    
    // Substitute <port> with the first detected open port (or comma-separated list if multiple)
    if (openPorts != null && openPorts.Any())
    {
        var portString = openPorts.Count == 1 ? openPorts[0].ToString() : string.Join(",", openPorts);
        result = Regex.Replace(result, @"<port>", portString, RegexOptions.IgnoreCase);
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
    string? IpRange,             // IP range for variable substitution
    string? SessionId            // Session ID to retrieve stored IP range
);
public record Session(string Id, string Name, string? IpRange = null);
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
            $"nmap --top-ports 100 -oX nmap_quick.xml {ip}",
            "Fast discovery (~30 seconds). Great for initial enumeration of most common services.");

        // Standard recommended scan
        yield return new("Standard Scan (Recommended)",
            $"nmap -sV -sC -oX nmap_standard.xml {ip}",
            "Top 1000 ports with version detection and default scripts (~2-5 minutes). Best starting point.");

        // Full TCP scan (with better settings)
        var fullScanPrefix = os.Equals("Windows", StringComparison.OrdinalIgnoreCase) ? "" : "sudo ";
        yield return new("Full TCP Scan",
            $"{fullScanPrefix}nmap -sS -p- --min-rate 5000 -T4 -oX nmap_all_ports.xml {ip}",
            "Comprehensive scan of all 65,535 TCP ports (~20-40 minutes). Use sudo for faster SYN scan on Linux/Unix.");

        // UDP scan
        yield return new("Top UDP Ports",
            $"sudo nmap -sU --top-ports 100 -oX nmap_udp.xml {ip}",
            "UDP is slower; scan top 100 ports for DNS/SNMP/DHCP/NTP (~5-10 minutes).");

        // OS-specific post-scan enumeration notes (only if OS is known)
        if (os.Equals("Windows", StringComparison.OrdinalIgnoreCase)) {
            yield return new("Windows Enumeration Tips", "N/A",
                "After scan: Check SMB (445) with smbclient/enum4linux, RDP (3389) cipher strength, WinRM (5985/5986).");
        } else if (os.Equals("Linux", StringComparison.OrdinalIgnoreCase)) {
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
    /// <summary>
    /// Parses Nmap XML output that may contain multiple hosts.
    /// Returns a list of HostScanResult, one per discovered host with open ports.
    /// </summary>
    public static List<HostScanResult> ParseMultipleHosts(string xmlOutput)
    {
        var hosts = new List<HostScanResult>();
        xmlOutput = xmlOutput?.Trim() ?? "";
        
        if (string.IsNullOrWhiteSpace(xmlOutput))
            return hosts;
        
        try
        {
            var doc = XDocument.Parse(xmlOutput);
            var hostElements = doc.Descendants("host");
            
            foreach (var hostElement in hostElements)
            {
                // Get host status - skip if down
                var statusElement = hostElement.Element("status");
                if (statusElement?.Attribute("state")?.Value != "up")
                    continue;
                
                // Get IP address
                var addressElement = hostElement.Descendants("address")
                    .FirstOrDefault(a => a.Attribute("addrtype")?.Value == "ipv4");
                if (addressElement == null)
                    continue;
                    
                var ipAddress = addressElement.Attribute("addr")?.Value;
                if (string.IsNullOrWhiteSpace(ipAddress))
                    continue;
                
                // Get hostname(s)
                var hostnameElement = hostElement.Descendants("hostname").FirstOrDefault();
                var hostname = hostnameElement?.Attribute("name")?.Value;
                
                // Parse open ports
                var ports = new List<OpenPort>();
                var portElements = hostElement.Descendants("port")
                    .Where(p => p.Element("state")?.Attribute("state")?.Value == "open");
                
                foreach (var portElement in portElements)
                {
                    var portId = portElement.Attribute("portid")?.Value;
                    var protocol = portElement.Attribute("protocol")?.Value ?? "tcp";
                    
                    if (!int.TryParse(portId, out var portNumber) || portNumber < 1 || portNumber > 65535)
                        continue;
                    
                    var serviceElement = portElement.Element("service");
                    var serviceName = serviceElement?.Attribute("name")?.Value;
                    var product = serviceElement?.Attribute("product")?.Value;
                    var version = serviceElement?.Attribute("version")?.Value;
                    
                    // Build version string from product and version
                    string? versionString = null;
                    if (!string.IsNullOrWhiteSpace(product) && !string.IsNullOrWhiteSpace(version))
                        versionString = $"{product} {version}";
                    else if (!string.IsNullOrWhiteSpace(product))
                        versionString = product;
                    else if (!string.IsNullOrWhiteSpace(version))
                        versionString = version;
                    
                    ports.Add(new OpenPort(
                        portNumber,
                        protocol,
                        string.IsNullOrWhiteSpace(serviceName) ? null : serviceName,
                        versionString
                    ));
                }
                
                // Skip hosts with no open ports
                if (!ports.Any())
                    continue;
                
                // Extract OS information
                string? detectedOS = null;
                var osElement = hostElement.Descendants("osmatch").FirstOrDefault();
                if (osElement != null)
                {
                    var osName = osElement.Attribute("name")?.Value;
                    var accuracy = osElement.Attribute("accuracy")?.Value;
                    if (!string.IsNullOrWhiteSpace(osName))
                        detectedOS = accuracy != null ? $"{osName} ({accuracy}% accuracy)" : osName;
                }
                
                // Extract SMB/NetBIOS information from script output
                string? domainName = null;
                string? computerName = null;
                string? fqdn = null;
                
                var scripts = hostElement.Descendants("script");
                foreach (var script in scripts)
                {
                    var scriptId = script.Attribute("id")?.Value;
                    var output = script.Attribute("output")?.Value ?? "";
                    
                    if (scriptId == "smb-os-discovery" || scriptId == "smb2-capabilities")
                    {
                        // Parse script output for domain/computer names
                        foreach (var line in output.Split('\n'))
                        {
                            if (line.Contains("Domain name:", StringComparison.OrdinalIgnoreCase))
                            {
                                var parts = line.Split(':', 2);
                                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                                    domainName = parts[1].Trim();
                            }
                            else if (line.Contains("Computer name:", StringComparison.OrdinalIgnoreCase))
                            {
                                var parts = line.Split(':', 2);
                                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                                    computerName = parts[1].Trim();
                            }
                            else if (line.Contains("FQDN:", StringComparison.OrdinalIgnoreCase))
                            {
                                var parts = line.Split(':', 2);
                                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[1]))
                                    fqdn = parts[1].Trim();
                            }
                        }
                    }
                }
                
                hosts.Add(new HostScanResult(
                    ipAddress,
                    hostname,
                    ports,
                    domainName,
                    computerName,
                    fqdn,
                    detectedOS
                ));
            }
        }
        catch (System.Xml.XmlException)
        {
            return new List<HostScanResult>();
        }
        catch (Exception)
        {
            return new List<HostScanResult>();
        }
        
        return hosts;
    }
}

public record HostScanResult(string IpAddress, string? Hostname, List<OpenPort> Ports, string? DomainName, string? ComputerName, string? FQDN, string? DetectedOS);

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
