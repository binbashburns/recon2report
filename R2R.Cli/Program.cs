using System.Net.Http.Json;

// Minimal CLI client that drives the Phase 1 API for demo/testing.
var baseUrl = Environment.GetEnvironmentVariable("R2R_API_BASE") ?? "http://localhost:5258/";
var api = new HttpClient { BaseAddress = new Uri(baseUrl) };

// Display ASCII art banner
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine(@"
                               ___                             __ 
   ________  _________  ____  |__ \________  ____  ____  _____/ /_
  / ___/ _ \/ ___/ __ \/ __ \ __/ / ___/ _ \/ __ \/ __ \/ ___/ __/
 / /  /  __/ /__/ /_/ / / / // __/ /  /  __/ /_/ / /_/ / /  / /_  
/_/   \___/\___/\____/_/ /_//_____/   \___/ .___/\____/_/   \__/  
                                         /_/                      
");
Console.ForegroundColor = ConsoleColor.Magenta;
Console.WriteLine("        Penetration Testing Reconnaissance Workflow");
Console.ResetColor();
Console.WriteLine();

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
if (!tgtResp.IsSuccessStatusCode)
{
    var error = await tgtResp.Content.ReadAsStringAsync();
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Error creating target: {error}");
    Console.ResetColor();
    return;
}
var target = await tgtResp.Content.ReadFromJsonAsync<Target>();
Console.WriteLine($"Target: {target!.Id} {target.Ip} ({target.Os})");

// Fetch scan commands from API
var cmdResp = await api.PostAsJsonAsync("nmap/suggest", new { Ip = target.Ip, Os = target.Os });
var cmds = await cmdResp.Content.ReadFromJsonAsync<List<NmapCommand>>();
if (cmds == null || !cmds.Any())
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("Error: Could not fetch scan commands from API.");
    Console.ResetColor();
    return;
}

// Filter out tip/note commands (those with "N/A" as command)
var scanCommands = cmds.Where(c => c.Command != "N/A").ToList();
var enumTips = cmds.Where(c => c.Command == "N/A").ToList();

// Display scan strategy menu
Console.WriteLine("\n" + new string('=', 60));
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("Select your Nmap scan strategy:");
Console.ResetColor();

for (int i = 0; i < scanCommands.Count; i++)
{
    var cmd = scanCommands[i];
    Console.WriteLine($"  {i + 1}. {cmd.Title}");
}
Console.WriteLine($"  {scanCommands.Count + 1}. Custom Port List");
Console.WriteLine($"  {scanCommands.Count + 2}. Show all details");

Console.Write($"\nChoice [1-{scanCommands.Count + 2}]: ");
var scanChoice = Console.ReadLine()?.Trim() ?? "2";

string scanCommand = "";
string scanExplanation = "";

if (int.TryParse(scanChoice, out int choice) && choice >= 1 && choice <= scanCommands.Count)
{
    // User selected one of the API-provided commands
    var selected = scanCommands[choice - 1];
    scanCommand = selected.Command;
    scanExplanation = selected.Explanation;
}
else if (choice == scanCommands.Count + 1)
{
    // Custom port list
    Console.Write("Enter comma-separated ports (e.g., 22,80,443): ");
    var customPorts = Console.ReadLine()?.Trim() ?? "22,80,443";
    scanCommand = $"nmap -p {customPorts} -sV -sC -oN nmap_custom.txt {target.Ip}";
    scanExplanation = "Targeted scan of specific ports with version detection.";
}
else if (choice == scanCommands.Count + 2)
{
    // Show all details
    Console.WriteLine("\n" + new string('=', 60));
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("All Suggested Nmap Commands:");
    Console.ResetColor();
    foreach (var c in cmds!) {
        Console.WriteLine($"\n[{c.Title}]\n{c.Command}\n- {c.Explanation}");
    }
    Console.WriteLine("\n" + new string('=', 60));
    Console.WriteLine("\nRun your scans, then paste Nmap normal output (end with a single line containing only 'EOF'):");
    goto SkipScanDisplay;
}
else
{
    // Default to second option (Standard Scan)
    var selected = scanCommands[1];
    scanCommand = selected.Command;
    scanExplanation = selected.Explanation;
}

Console.WriteLine("\n" + new string('=', 60));
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("Recommended Nmap Command:");
Console.ResetColor();
Console.WriteLine($"\n{scanCommand}\n");
Console.ForegroundColor = ConsoleColor.DarkGray;
Console.WriteLine($"→ {scanExplanation}");
Console.ResetColor();

// Show enumeration tips if available
if (enumTips.Any())
{
    Console.WriteLine();
    foreach (var tip in enumTips)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"💡 {tip.Title}:");
        Console.ResetColor();
        Console.WriteLine($"   {tip.Explanation}");
    }
}

Console.WriteLine(new string('=', 60));

SkipScanDisplay:
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
var nextResp = await api.PostAsJsonAsync("next-steps", new { Ip = target.Ip, Os = target.Os, Ports = ports });
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
