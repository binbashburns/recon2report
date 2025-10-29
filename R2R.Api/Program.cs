using System.Text.RegularExpressions;

// Bootstraps the minimal API host and exposes Swagger for interactive testing.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

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

// ---- Helper: Suggest Nmap commands (with explanations) ----
// Generates a curated list of scan commands based on IP/OS selections.
app.MapPost("/nmap/suggest", (SuggestRequest req) => {
    var cmds = NmapCommandBuilder.Build(req.Ip, req.Os);
    return Results.Ok(cmds);
});

// ---- Helper: Parse pasted Nmap normal output ----
// Converts raw Nmap output into structured `OpenPort` records.
app.MapPost("/nmap/parse", (ParseRequest req) => {
    var parsed = NmapParser.Parse(req.NmapOutput ?? "");
    return Results.Ok(parsed);
});

// ---- Helper: Next-step suggestions from OS + ports ----
// Converts the OS + open ports into actionable enumeration recommendations.
app.MapPost("/next-steps", (NextStepsRequest req) => {
    var steps = NextStepsSuggester.Suggest(req.Ip, req.Os, req.Ports ?? []);
    return Results.Ok(steps);
});

// Activates the ASP.NET Core request pipeline.
app.Run();

// Request DTOs exposed to the front-end for helper endpoints.
public record SuggestRequest(string Ip, string Os); // Os: "Windows"|"Linux"
public record ParseRequest(string? NmapOutput);
public record NextStepsRequest(string Ip, string Os, List<OpenPort>? Ports);
public record Session(string Id, string Name);
public record Target(string Id, string SessionId, string Ip, string Os);

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
        var list = new List<OpenPort>();
        foreach (var raw in output.Split('\n')) {
            var line = raw.Trim();
            var m = PortLine.Match(line);
            if (!m.Success) continue;
            if (!int.TryParse(m.Groups["port"].Value, out var port) || port < 1 || port > 65535) continue;
            var proto   = m.Groups["proto"].Value;
            var state   = m.Groups["state"].Value;
            if (!string.Equals(state, "open", StringComparison.OrdinalIgnoreCase)) continue; // only “open” for next steps
            var service = m.Groups["service"].Value;
            var version = m.Groups["version"].Success ? m.Groups["version"].Value.Trim() : null;
            list.Add(new OpenPort(port, proto, string.IsNullOrWhiteSpace(service) ? null : service, version));
        }
        // dedupe same port/proto pairs (keep first with version)
        return list
            .GroupBy(p => (p.Number, p.Protocol.ToLowerInvariant()))
            .Select(g => g.First())
            .OrderBy(p => p.Number)
            .ToList();
    }
}

// Suggests playbook steps by matching ports/OS against a curated checklist.
public static class NextStepsSuggester {
    public static IEnumerable<Suggestion> Suggest(string ip, string os, IEnumerable<OpenPort> ports)
    {
        // Use a set for constant-time checks when matching well-known services.
        var set = ports.Select(p => p.Number).ToHashSet();

        // General
        yield return new("General", "Take note of service versions; search for matching exploits. Prefer non-MSF first.");
        // Web
        foreach (var p in ports.Where(p => new[] {80, 443, 8080, 8443}.Contains(p.Number))) {
            yield return new("Web", $"http enum (NSE): nmap --script http-enum,http-title -p {p.Number} {ip}");
            yield return new("Web", $"dir brute: gobuster dir -u http://{ip}:{p.Number} -w <wordlist>");
            yield return new("Web", $"tech: whatweb http://{ip}:{p.Number}");
        }
        // SMB
        if (set.Contains(445) || set.Contains(139)) {
            yield return new("SMB", $"enum: smbclient -L //{ip} -N");
            yield return new("SMB", $"enum: enum4linux-ng -A {ip}");
        }
        // SSH
        if (set.Contains(22)) {
            yield return new("SSH", $"ssh-audit {ip}  # check ciphers/banner");
        }
        // RDP
        if (set.Contains(3389)) {
            yield return new("RDP", $"nmap --script rdp-enum-encryption -p3389 {ip}");
        }
        // DNS
        if (set.Contains(53)) {
            yield return new("DNS", $"dig axfr @{ip} <domain>  # (labs only) try zone transfer");
        }
        // PrivEsc checklists (textual nudge only)
        if (os.Equals("Linux", StringComparison.OrdinalIgnoreCase)) {
            yield return new("PrivEsc", "Run linpeas; check SUID, cron, sudo -l, capabilities, Docker group, NFS.");
        } else {
            yield return new("PrivEsc", "Run winPEAS; check unquoted service paths, AlwaysInstallElevated, UAC, privileges.");
        }
    }
}
// Lightweight DTO returned from `/next-steps`.
public record Suggestion(string Area, string Tip);

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
