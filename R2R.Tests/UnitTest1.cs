using Xunit;
using R2R.Core.Domain;
using R2R.Core.Parsing;
using R2R.Core.Rules;

public class NmapParserTests
{
    [Fact]
    public void ParsesOpenPortsFromNormalOutput()
    {
        var sample = """
        Starting Nmap 7.94
        Nmap scan report for 10.10.10.10
        PORT     STATE SERVICE  VERSION
        22/tcp   open  ssh      OpenSSH 8.4p1
        80/tcp   open  http     Apache httpd 2.4.41
        111/tcp  closed rpcbind
        53/udp   open  domain
        """;

        var ports = NmapParser.Parse(sample);
        Assert.Contains(ports, p => p.Number == 22 && p.Protocol == "tcp" && p.Service == "ssh");
        Assert.Contains(ports, p => p.Number == 80 && p.Protocol == "tcp" && p.Service == "http");
        Assert.Contains(ports, p => p.Number == 53 && p.Protocol == "udp" && p.Service == "domain");
        Assert.DoesNotContain(ports, p => p.Number == 111); // closed filtered out
    }
}

public class MarkdownParserTests
{
    [Fact]
    public void ParsesSimpleMarkdownIntoRuleSet()
    {
        var markdown = """
        # Test Rules
        
        ## Scan network >>> Vulnerable host
        - `nmap -sP <ip>`
        - `nxc smb <ip_range>`
        
        ## Anonymous SMB >>> Username
        - `smbclient -L //<ip> -N`
        """;

        var ruleSet = MarkdownRuleLoader.ParseMarkdown("test", markdown);
        
        Assert.Equal("test", ruleSet.Id);
        Assert.Equal(2, ruleSet.Vectors.Count);
        
        var scanVector = ruleSet.Vectors.First(v => v.Name == "Scan network");
        Assert.NotNull(scanVector);
        Assert.Contains("Vulnerable host", scanVector.PossibleOutcomes.Select(o => o.DisplayName));
        Assert.True(scanVector.Commands.Count >= 2);
    }
}

public class RuleEngineTests
{
    [Fact]
    public void EvaluatesNoCredsStateAndReturnsScanVectors()
    {
        var markdown = """
        # No Credentials
        
        ## Scan network >>> Vulnerable host
        - `nmap -sP <ip>`
        
        ## Anonymous SMB >>> Username
        - `smbclient -L //<ip> -N`
        """;

        var ruleSet = MarkdownRuleLoader.ParseMarkdown("no_creds", markdown);
        
        // Debug: verify the parser extracted vectors correctly
        Assert.NotEmpty(ruleSet.Vectors);
        Assert.Equal("nocreds", ruleSet.InitialState);
        
        var engine = new RuleEngine(new List<RuleSet> { ruleSet });

        var state = new AttackState(
            CurrentPhase: "nocreds",  // Match what parser generates
            AcquiredItems: new List<string>(),
            OpenPorts: new List<int>(),
            Services: new List<string>(),
            TargetOS: null
        );

        var vectors = engine.Evaluate(state);
        
        Assert.NotEmpty(vectors);
        Assert.Contains(vectors, v => v.Name.Contains("Scan network"));
    }

    [Fact]
    public void FiltersVectorsByOpenPorts()
    {
        var markdown = """
        # No Credentials
        
        ## Scan network
        - `nmap -sP <ip>`
        
        ## Anonymous SMB access
        - `smbclient -L //<ip> -N`
        """;

        var ruleSet = MarkdownRuleLoader.ParseMarkdown("no_creds", markdown);
        var engine = new RuleEngine(new List<RuleSet> { ruleSet });

        var state = new AttackState(
            CurrentPhase: "nocreds",  // Match what parser generates
            AcquiredItems: new List<string>(),
            OpenPorts: new List<int> { 445, 139 },
            Services: new List<string>(),
            TargetOS: null
        );

        // First get all vectors that apply to this state
        var allVectors = engine.Evaluate(state);
        Assert.NotEmpty(allVectors);
        
        // Then filter by ports
        var vectors = engine.GetVectorsForPorts(state, new List<int> { 445 });
        
        // Should prioritize SMB-related vectors when port 445 is open
        Assert.Contains(vectors, v => v.Name.Contains("SMB", StringComparison.OrdinalIgnoreCase));
    }
}