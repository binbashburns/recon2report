using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Any;

namespace R2R.Api;

/// <summary>
/// Swagger/OpenAPI configuration and documentation examples for all API endpoints.
/// Provides rich context and examples to make the API self-documenting.
/// </summary>
public static class SwaggerConfiguration
{
    /// <summary>
    /// Configures Swagger generator with API metadata and documentation.
    /// </summary>
    public static void AddSwaggerDocumentation(this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Recon2Report API",
                Version = "v1",
                Description = @"
Context-aware penetration testing assistant that suggests attack vectors based on phase, discovered services, acquired items, and target OS.

**Workflow**: Session → Target → Nmap Suggestions → Parse Scan → Get Attack Vectors

**Key Features**: Service grouping, variable substitution, phase-aware filtering, multi-host support
",
                Contact = new OpenApiContact
                {
                    Name = "Recon2Report Project",
                    Url = new Uri("https://github.com/binbashburns/recon2report")
                }
            });

            // Add security definitions if needed in the future
            // options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme { ... });
        });
    }

    /// <summary>
    /// Enriches the /attack-paths/suggest endpoint with comprehensive examples.
    /// </summary>
    public static RouteHandlerBuilder WithAttackPathSuggestExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Get context-aware attack vector suggestions";
            operation.Description = @"
**Prerequisites**: Must have parsed Nmap scan results (POST /targets/{id}/scan) to get openPorts and services data.

Returns attack vectors filtered by phase, acquired items, open ports, services, and target OS.
Commands include automatic variable substitution (IP, domain, ports).

**Quick start**: Use example ""windows-no-creds"" with your target IP after uploading scan results.
";

            // Example 1: Initial reconnaissance (no credentials)
            var example1 = new OpenApiObject
            {
                ["currentPhase"] = new OpenApiString("no_creds"),
                ["acquiredItems"] = new OpenApiArray(),
                ["openPorts"] = new OpenApiArray
                {
                    new OpenApiInteger(445),
                    new OpenApiInteger(139),
                    new OpenApiInteger(88),
                    new OpenApiInteger(389)
                },
                ["services"] = new OpenApiArray
                {
                    new OpenApiString("smb"),
                    new OpenApiString("kerberos"),
                    new OpenApiString("ldap")
                },
                ["targetOS"] = new OpenApiString("Windows"),
                ["targetIp"] = new OpenApiString("192.168.1.10"),
                ["domainName"] = new OpenApiString("corp.local"),
                ["sessionId"] = new OpenApiString("session-123")
            };

            // Example 2: With credentials acquired
            var example2 = new OpenApiObject
            {
                ["currentPhase"] = new OpenApiString("user_found"),
                ["acquiredItems"] = new OpenApiArray
                {
                    new OpenApiString("username"),
                    new OpenApiString("password")
                },
                ["openPorts"] = new OpenApiArray
                {
                    new OpenApiInteger(445),
                    new OpenApiInteger(5985),
                    new OpenApiInteger(389)
                },
                ["services"] = new OpenApiArray
                {
                    new OpenApiString("smb"),
                    new OpenApiString("winrm"),
                    new OpenApiString("ldap")
                },
                ["targetOS"] = new OpenApiString("Windows"),
                ["targetIp"] = new OpenApiString("192.168.1.10"),
                ["domainName"] = new OpenApiString("corp.local"),
                ["sessionId"] = new OpenApiString("session-456")
            };

            // Example 3: Linux target with SSH
            var example3 = new OpenApiObject
            {
                ["currentPhase"] = new OpenApiString("no_creds"),
                ["acquiredItems"] = new OpenApiArray(),
                ["openPorts"] = new OpenApiArray
                {
                    new OpenApiInteger(22),
                    new OpenApiInteger(80),
                    new OpenApiInteger(443)
                },
                ["services"] = new OpenApiArray
                {
                    new OpenApiString("ssh"),
                    new OpenApiString("http"),
                    new OpenApiString("https")
                },
                ["targetOS"] = new OpenApiString("Linux"),
                ["targetIp"] = new OpenApiString("10.10.10.50"),
                ["sessionId"] = new OpenApiString("session-789")
            };

            // Add multiple examples
            operation.RequestBody.Content["application/json"].Examples = new Dictionary<string, OpenApiExample>
            {
                ["windows-no-creds"] = new OpenApiExample
                {
                    Summary = "Windows - no credentials",
                    Description = "Initial recon with SMB/Kerberos/LDAP exposed",
                    Value = example1
                },
                ["windows-with-creds"] = new OpenApiExample
                {
                    Summary = "Windows - with credentials",
                    Description = "After obtaining username and password",
                    Value = example2
                },
                ["linux-web-server"] = new OpenApiExample
                {
                    Summary = "Linux - SSH and web",
                    Description = "Web server with SSH access",
                    Value = example3
                }
            };

            return operation;
        });
    }

    /// <summary>
    /// Enriches the /nmap/suggest endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithNmapSuggestExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Get curated Nmap scan commands";
            operation.Description = "Returns prioritized Nmap commands (quick scan → full scan) with runtime estimates. No prerequisites.";

            var exampleRequest = new OpenApiObject
            {
                ["ip"] = new OpenApiString("192.168.1.10"),
                ["os"] = new OpenApiString("Windows")
            };

            operation.RequestBody.Content["application/json"].Example = exampleRequest;

            return operation;
        });
    }

    /// <summary>
    /// Enriches the /sessions endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithSessionExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Create a new penetration testing session";
            operation.Description = "**Start here**. Creates a session to group all targets and scan results. Optional: Add IP range for network-wide attack vectors.";

            var exampleRequest = new OpenApiObject
            {
                ["id"] = new OpenApiString(""),
                ["name"] = new OpenApiString("ACME Corp Internal Pentest - Q4 2025"),
                ["ipRange"] = new OpenApiString("192.168.1.0/24")
            };

            operation.RequestBody.Content["application/json"].Example = exampleRequest;

            return operation;
        });
    }

    /// <summary>
    /// Enriches the /targets endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithTargetExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Add a target host to a session";
            operation.Description = "**Prerequisites**: Must have a session (POST /sessions). Creates a target with IP and OS. Ports are added later via scan upload.";

            var exampleRequest = new OpenApiObject
            {
                ["id"] = new OpenApiString(""),
                ["sessionId"] = new OpenApiString("abc123"),
                ["ip"] = new OpenApiString("192.168.1.10"),
                ["os"] = new OpenApiString("Windows")
            };

            operation.RequestBody.Content["application/json"].Example = exampleRequest;

            return operation;
        });
    }

    /// <summary>
    /// Enriches the /targets/{id}/scan endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithScanUploadExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Upload and parse Nmap XML output";
            operation.Description = @"
**Prerequisites**: Must have a target (POST /targets).

Parses Nmap XML to extract open ports, services, hostnames, OS detection, and SMB/NetBIOS info.
Creates separate targets if multiple hosts detected.

**Tip**: Run Nmap with `-oX filename.xml` to generate XML output.
";

            var exampleXml = @"<?xml version=""1.0""?>
<nmaprun>
  <host>
    <status state=""up""/>
    <address addr=""192.168.1.10"" addrtype=""ipv4""/>
    <hostnames>
      <hostname name=""dc01.corp.local""/>
    </hostnames>
    <ports>
      <port protocol=""tcp"" portid=""445"">
        <state state=""open""/>
        <service name=""microsoft-ds"" product=""Windows Server 2019""/>
      </port>
      <port protocol=""tcp"" portid=""88"">
        <state state=""open""/>
        <service name=""kerberos""/>
      </port>
    </ports>
  </host>
</nmaprun>";

            var exampleRequest = new OpenApiObject
            {
                ["nmapOutput"] = new OpenApiString(exampleXml)
            };

            operation.RequestBody.Content["application/json"].Example = exampleRequest;

            return operation;
        });
    }

    /// <summary>
    /// Enriches the /attack-paths/all endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithAttackPathsAllExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Get all attack vectors for a phase (reference mode)";
            operation.Description = @"
No prerequisites. Returns ALL attack vectors for a phase without filtering.

**Use for**: Reference sheets, learning techniques, pre-scan planning.

Commands show raw syntax with placeholders (`<ip>`, `<domain>`, `<port>`).

**Phases**: reconnaissance, no_creds, user_found, admin_access, post_exploitation
";

            return operation;
        });
    }

    /// <summary>
    /// Enriches the POST /evidence endpoint with examples.
    /// </summary>
    public static RouteHandlerBuilder WithEvidenceExamples(this RouteHandlerBuilder builder)
    {
        return builder.WithOpenApi(operation =>
        {
            operation.Summary = "Upload evidence (screenshot/data) for report generation";
            operation.Description = @"
**Prerequisites**: Must have a target (POST /targets).

Stores evidence with base64-encoded image data for penetration test reports.

**Validation**:
- Image format: PNG, JPG, JPEG, GIF
- Size limit: 5MB maximum
- Data URL format: `data:image/{type};base64,{data}`

**Valid stages**: information_gathering, enumeration, exploitation, privilege_escalation, post_exploitation, maintaining_access, house_cleaning

**Testing tip**: Use a tool like `base64 -i screenshot.png` (macOS/Linux) or convert your image to base64, then format as `data:image/png;base64,{YOUR_BASE64_HERE}`
";

            // Create a valid base64 PNG (50x50 gradient square - ~400 bytes, realistic for testing)
            var sampleBase64 = "iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEgAACxIB0t1+/AAAABx0RVh0U29mdHdhcmUAQWRvYmUgRmlyZXdvcmtzIENTNui8sowAAAAWdEVYdENyZWF0aW9uIFRpbWUAMDMvMTQvMTNJ5sWcAAAAvElEQVRoge3YsQ2AMAxE0RNYgJUZgE0ZgX1ZhQlYgAr3FkSRECDEv5LOsiXn3Vmymz5ERERERERERERERERERERERERERERERERERERERERE9GsN2Cv2kJ1iH9kZ9pPdYE/ZHfaVvWBv2Qc2lH1hb9kXNpZ9YXPZFzaYfWGT2Rc2mn1hs9kXNpx9YdPZFzaefWHz2Rc+gH3hE9gXPoJ94TPYF76Dfek72Je+g33pO9iXvoN96TsRERERERERERE9ugFRmzIbCwplbQAAAABJRU5ErkJggg==";
            
            var exampleRequest = new OpenApiObject
            {
                ["targetId"] = new OpenApiString("abc123"),
                ["stage"] = new OpenApiString("exploitation"),
                ["caption"] = new OpenApiString("Successful remote code execution via SMB exploit - reverse shell obtained"),
                ["dataUrl"] = new OpenApiString($"data:image/png;base64,{sampleBase64}")
            };

            operation.RequestBody.Content["application/json"].Example = exampleRequest;

            return operation;
        });
    }
}
