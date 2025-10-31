using Xunit;
using R2R.Core.Domain;
using R2R.Core.Parsing;
using R2R.Core.Rules;

public class NmapParserTests
{
    [Fact]
    public void ParsesOpenPortsFromXmlOutput()
    {
        var sample = """
        <?xml version="1.0" encoding="UTF-8"?>
        <nmaprun scanner="nmap" args="nmap -sV 10.10.10.10" version="7.94">
        <host>
            <status state="up"/>
            <address addr="10.10.10.10" addrtype="ipv4"/>
            <hostnames>
                <hostname name="test.example.com"/>
            </hostnames>
            <ports>
                <port protocol="tcp" portid="22">
                    <state state="open"/>
                    <service name="ssh" product="OpenSSH" version="8.4p1"/>
                </port>
                <port protocol="tcp" portid="80">
                    <state state="open"/>
                    <service name="http" product="Apache httpd" version="2.4.41"/>
                </port>
                <port protocol="tcp" portid="111">
                    <state state="closed"/>
                    <service name="rpcbind"/>
                </port>
                <port protocol="udp" portid="53">
                    <state state="open"/>
                    <service name="domain"/>
                </port>
            </ports>
        </host>
        </nmaprun>
        """;

        var hosts = NmapParser.ParseMultipleHosts(sample);
        Assert.Single(hosts); // Should find exactly one host
        var ports = hosts[0].Ports;
        Assert.Contains(ports, p => p.Number == 22 && p.Protocol == "tcp" && p.Service == "ssh");
        Assert.Contains(ports, p => p.Number == 80 && p.Protocol == "tcp" && p.Service == "http");
        Assert.Contains(ports, p => p.Number == 53 && p.Protocol == "udp" && p.Service == "domain");
        Assert.DoesNotContain(ports, p => p.Number == 111); // closed filtered out
    }
}

public class ServiceRuleLoaderTests
{
    [Fact]
    public void ParsesJsonIntoServiceRuleSet()
    {
        var json = """
        {
          "service": "test-service",
          "description": "Test service for unit testing",
          "ports": [22, 80],
          "serviceNames": ["ssh", "http"],
          "targetOs": ["linux", "windows"],
          "vectors": [
            {
              "id": "test-scan",
              "name": "Network Scan",
              "phase": "reconnaissance",
              "prerequisites": ["network_access"],
              "description": "Scan the network for hosts",
              "commands": [
                {
                  "tool": "nmap",
                  "command": "nmap -sP <ip>",
                  "description": "Ping scan"
                }
              ],
              "outcomes": ["hosts_discovered"]
            },
            {
              "id": "test-smb",
              "name": "Anonymous SMB Access",
              "phase": "reconnaissance",
              "prerequisites": ["network_access"],
              "description": "Test anonymous SMB access",
              "commands": [
                {
                  "tool": "smbclient",
                  "command": "smbclient -L //<ip> -N",
                  "description": "List SMB shares"
                }
              ],
              "outcomes": ["credential_access"]
            }
          ]
        }
        """;

        var ruleSet = ServiceRuleLoader.LoadFromJson(json);
        
        Assert.Equal("test-service", ruleSet.Service);
        Assert.Equal(2, ruleSet.Vectors.Count);
        Assert.Contains(22, ruleSet.Ports);
        Assert.Contains(80, ruleSet.Ports);
        
        var scanVector = ruleSet.Vectors.First(v => v.Name == "Network Scan");
        Assert.NotNull(scanVector);
        Assert.Contains("hosts_discovered", scanVector.PossibleOutcomes.Select(o => o.StateId));
        Assert.Single(scanVector.Commands);
    }
}

public class ServiceRuleEngineTests
{
    [Fact]
    public void LoadsOnlyRelevantServicesBasedOnPorts()
    {
        var sshJson = """
        {
          "service": "ssh",
          "description": "SSH service attacks",
          "ports": [22],
          "serviceNames": ["ssh"],
          "targetOs": ["linux", "windows"],
          "vectors": [
            {
              "id": "ssh-scan",
              "name": "SSH Enumeration",
              "phase": "reconnaissance",
              "prerequisites": ["network_access"],
              "description": "Enumerate SSH",
              "commands": [{"tool": "nmap", "command": "nmap -p22 <ip>", "description": "Scan SSH"}],
              "outcomes": ["information_gathered"]
            }
          ]
        }
        """;

        var httpJson = """
        {
          "service": "http",
          "description": "HTTP service attacks",
          "ports": [80, 443],
          "serviceNames": ["http", "https"],
          "targetOs": ["linux", "windows"],
          "vectors": [
            {
              "id": "http-scan",
              "name": "Web Directory Bruteforce",
              "phase": "reconnaissance",
              "prerequisites": ["network_access"],
              "description": "Bruteforce directories",
              "commands": [{"tool": "gobuster", "command": "gobuster dir -u http://<ip>", "description": "Scan dirs"}],
              "outcomes": ["information_gathered"]
            }
          ]
        }
        """;

        var sshRuleSet = ServiceRuleLoader.LoadFromJson(sshJson);
        var httpRuleSet = ServiceRuleLoader.LoadFromJson(httpJson);
        var engine = new ServiceRuleEngine(new List<ServiceRuleSet> { sshRuleSet, httpRuleSet });

        // State with only port 80 open - should only load HTTP service
        var state = new AttackState(
            CurrentPhase: "reconnaissance",
            AcquiredItems: new List<string> { "network_access" },
            OpenPorts: new List<int> { 80 },
            Services: new List<string> { "http" },
            TargetOS: "linux"
        );

        var vectors = engine.Evaluate(state).ToList();
        
        Assert.NotEmpty(vectors);
        Assert.Contains(vectors, v => v.Name.Contains("Web"));
        Assert.DoesNotContain(vectors, v => v.Name.Contains("SSH"));
    }

    [Fact]
    public void FiltersVectorsByPhaseAndPrerequisites()
    {
        var json = """
        {
          "service": "smb",
          "description": "SMB attacks",
          "ports": [445],
          "serviceNames": ["microsoft-ds"],
          "targetOs": ["windows"],
          "vectors": [
            {
              "id": "smb-anon",
              "name": "Anonymous SMB Enumeration",
              "phase": "reconnaissance",
              "prerequisites": ["network_access"],
              "description": "Anonymous SMB access",
              "commands": [{"tool": "smbclient", "command": "smbclient -L //<ip> -N", "description": "List shares"}],
              "outcomes": ["information_gathered"]
            },
            {
              "id": "smb-auth",
              "name": "Authenticated SMB Enumeration",
              "phase": "credential_access",
              "prerequisites": ["valid_credentials"],
              "description": "Enumerate with creds",
              "commands": [{"tool": "nxc", "command": "nxc smb <ip> -u <user> -p <pass>", "description": "Enumerate"}],
              "outcomes": ["credential_access"]
            }
          ]
        }
        """;

        var ruleSet = ServiceRuleLoader.LoadFromJson(json);
        var engine = new ServiceRuleEngine(new List<ServiceRuleSet> { ruleSet });

        // State in reconnaissance phase without valid credentials
        var state = new AttackState(
            CurrentPhase: "reconnaissance",
            AcquiredItems: new List<string> { "network_access" },
            OpenPorts: new List<int> { 445 },
            Services: new List<string> { "microsoft-ds" },
            TargetOS: "windows"
        );

        var vectors = engine.Evaluate(state).ToList();
        
        // Should only return reconnaissance vectors with network_access prerequisite
        Assert.NotEmpty(vectors);
        Assert.Contains(vectors, v => v.Name.Contains("Anonymous"));
        Assert.DoesNotContain(vectors, v => v.Name.Contains("Authenticated"));
    }
}