using System.Net.Http.Json;

// Minimal CLI client that drives the Phase 1 API for demo/testing.
var baseUrl = Environment.GetEnvironmentVariable("R2R_API_BASE") ?? "http://localhost:5258/";
var api = new HttpClient { BaseAddress = new Uri(baseUrl) };

Console.WriteLine("R2R — Recon2Report (CLI)");
Console.Write("Name this session: ");
var name = Console.ReadLine() ?? "Lab";

var sessResp = await api.PostAsJsonAsync("sessions", new { Id = "", Name = name });
sessResp.EnsureSuccessStatusCode();
var session = await sessResp.Content.ReadFromJsonAsync<Session>();
Console.WriteLine($"Session: {session!.Id}");

Console.Write("Target IP: ");
var ip = Console.ReadLine() ?? "";
Console.Write("OS (Windows/Linux): ");
var os = Console.ReadLine() ?? "Linux";

var tgtResp = await api.PostAsJsonAsync("targets", new { Id = "", SessionId = session.Id, Ip = ip, Os = os });
tgtResp.EnsureSuccessStatusCode();
var target = await tgtResp.Content.ReadFromJsonAsync<Target>();
Console.WriteLine($"Target: {target!.Id} {target.Ip} ({target.Os})");

// Surface the API's canned Nmap workflow so the operator can copy/paste.
Console.WriteLine("\nSuggested Nmap commands:");
var cmdResp = await api.PostAsJsonAsync("nmap/suggest", new { Ip = target.Ip, Os = target.Os });
var cmds = await cmdResp.Content.ReadFromJsonAsync<List<NmapCommand>>();
foreach (var c in cmds!) {
    Console.WriteLine($"\n[{c.Title}]\n{c.Command}\n- {c.Explanation}");
}

Console.WriteLine("\nRun your scans, then paste Nmap normal output (end with a single line containing only 'EOF'):");
var buf = new List<string>();
while (true) {
    var line = Console.ReadLine();
    if (line == null) break;
    if (line.Trim() == "EOF") break;
    buf.Add(line);
}
var paste = string.Join("\n", buf);

// Send the pasted scan results to the parsing helper.
var parseResp = await api.PostAsJsonAsync("nmap/parse", new { NmapOutput = paste });
var ports = await parseResp.Content.ReadFromJsonAsync<List<OpenPort>>();
Console.WriteLine($"\nOpen ports detected: {ports!.Count}");
foreach (var p in ports) Console.WriteLine($"- {p.Protocol}/{p.Number} {p.Service} {p.Version}");

// Ask the API for the generalized follow-up checklist.
Console.WriteLine("\nNext steps (generalized):");
var nextResp = await api.PostAsJsonAsync("next-steps", new { Os = target.Os, Ports = ports });
var tips = await nextResp.Content.ReadFromJsonAsync<List<Suggestion>>();
foreach (var t in tips!) Console.WriteLine($"[{t.Area}] {t.Tip}");

// (Demonstrate CRUD to satisfy rubric)
// Quick update demo shows PUT wiring end-to-end.
Console.Write("\nDo you want to update the target OS? (y/N) ");
if ((Console.ReadLine() ?? "").Trim().ToLower() == "y") {
    Console.Write("New OS: ");
    var newOs = Console.ReadLine() ?? target.Os;
    var put = await api.PutAsJsonAsync($"targets/{target.Id}", new { Id = target.Id, SessionId = session.Id, Ip = target.Ip, Os = newOs });
    Console.WriteLine(put.IsSuccessStatusCode ? "Updated." : "Update failed.");
}
// And delete to complete the CRUD story.
Console.Write("\nDelete target to demo CRUD? (y/N) ");
if ((Console.ReadLine() ?? "").Trim().ToLower() == "y") {
    var del = await api.DeleteAsync($"targets/{target.Id}");
    Console.WriteLine(del.IsSuccessStatusCode ? "Deleted." : "Delete failed.");
}

Console.WriteLine("\nDone");

// Local DTOs (mirror API)
record Session(string Id, string Name);
record Target(string Id, string SessionId, string Ip, string Os);
record OpenPort(int Number, string Protocol, string? Service, string? Version);
record NmapCommand(string Title, string Command, string Explanation);
record Suggestion(string Area, string Tip);
