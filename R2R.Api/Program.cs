using System.Text.RegularExpressions;

// Bootstraps the minimal API host and exposes basic OpenAPI metadata.
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();
app.MapOpenApi(); // Exposes OpenAPI JSON at /openapi/v1.json (requires Microsoft.AspNetCore.OpenApi).

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
    var steps = NextStepsSuggester.Suggest(req.Os, req.Ports ?? []);
    return Results.Ok(steps);
});

// Activates the ASP.NET Core request pipeline.
app.Run();

// Request DTOs exposed to the front-end for helper endpoints.
public record SuggestRequest(string Ip, string Os); // Os: "Windows"|"Linux"
public record ParseRequest(string? NmapOutput);
public record NextStepsRequest(string Os, List<OpenPort>? Ports);
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
        yield return new("Full TCP fast sweep",
            $"nmap -p- --min-rate 10000 -oN nmap_all_tcp.txt {ip}",
            "Discovers open TCP ports quickly; increase --min-rate for speed, decrease for accuracy.");

        yield return new("Default scripts & versions",
            $"nmap -sC -sV -oN nmap_default_scripts.txt {ip}",
            "Runs default NSE scripts and grabs service versions to guide enumeration.");

        yield return new("Top 200 UDP",
            $"sudo nmap -sU --top-ports 200 -oN nmap_top_udp.txt {ip}",
            "UDP is slower and lossy; start with top ports to catch DNS/SNMP/NTP/..");

        // Tiny OS-specific nudge (purely textual)
        if (os.Equals("Windows", StringComparison.OrdinalIgnoreCase)) {
            yield return new("Windows note", "N/A",
                "If RDP (3389) or SMB (445) appear, plan SMB/RPC/RDP checks and Windows privesc later.");
        } else {
            yield return new("Linux note", "N/A",
                "If SSH (22) or web (80/443/8080) appear, plan enum (ssh-audit, gobuster, http-* NSE).");
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
    public static IEnumerable<Suggestion> Suggest(string os, IEnumerable<OpenPort> ports)
    {
        // Use a set for constant-time checks when matching well-known services.
        var set = ports.Select(p => p.Number).ToHashSet();

        // General
        yield return new("General", "Take note of service versions; search for matching exploits. Prefer non-MSF first.");
        // Web
        foreach (var p in ports.Where(p => new[] {80, 443, 8080, 8443}.Contains(p.Number))) {
            yield return new("Web", $"http enum (NSE): nmap --script http-enum,http-title -p {p.Number} <IP>");
            yield return new("Web", $"dir brute: gobuster dir -u http://<IP>:{p.Number} -w <wordlist>");
            yield return new("Web", $"tech: whatweb http://<IP>:{p.Number}");
        }
        // SMB
        if (set.Contains(445) || set.Contains(139)) {
            yield return new("SMB", "enum: smbclient -L //<IP> -N");
            yield return new("SMB", "enum: enum4linux-ng -A <IP>");
        }
        // SSH
        if (set.Contains(22)) {
            yield return new("SSH", "ssh-audit <IP>  # check ciphers/banner");
        }
        // RDP
        if (set.Contains(3389)) {
            yield return new("RDP", "nmap --script rdp-enum-encryption -p3389 <IP>");
        }
        // DNS
        if (set.Contains(53)) {
            yield return new("DNS", "dig axfr @<IP> <domain>  # (labs only) try zone transfer");
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
