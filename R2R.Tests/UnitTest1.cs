using Xunit;

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

public class NextStepsTests
{
    [Fact]
    public void SuggestsWebEnumForWebPorts()
    {
        var ports = new[]{ new OpenPort(80,"tcp","http","Apache") };
        var tips = NextStepsSuggester.Suggest("Linux", ports).ToList();
        Assert.Contains(tips, t => t.Area=="Web" && t.Tip.Contains("http-enum"));
    }

    [Fact]
    public void SuggestsLinuxOrWindowsPrivesc()
    {
        var none = Enumerable.Empty<OpenPort>();
        var linux = NextStepsSuggester.Suggest("Linux", none);
        var win   = NextStepsSuggester.Suggest("Windows", none);
        Assert.Contains(linux, t => t.Area=="PrivEsc" && t.Tip.Contains("linpeas"));
        Assert.Contains(win,   t => t.Area=="PrivEsc" && t.Tip.Contains("winPEAS"));
    }
}