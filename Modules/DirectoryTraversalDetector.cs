using System;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class DirectoryTraversalDetector : IScanModule
	{
		public string Name => "Directory Traversal Detection";
		public string Description => "Detects potential directory traversal vulnerabilities by attempting to access sensitive files.";
		public ScanSeverity Severity => ScanSeverity.High;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var baseUrl = $"http://{targetIp}";
				var pathsToCheck = new[]
				{
					"/../../../../etc/passwd",
					"/..%2f..%2f..%2f..%2fetc%2fpasswd",
					"/..\\..\\..\\..\\windows\\win.ini"
				};

				foreach (var path in pathsToCheck)
				{
					var url = baseUrl + path;
					var response = await client.GetAsync(url);
					if (response.IsSuccessStatusCode)
					{
						var content = await response.Content.ReadAsStringAsync();
						if (!string.IsNullOrWhiteSpace(content) &&
							(content.Contains("root:x:0:0:") || content.Contains("[fonts]")))
						{
							return new ScanResult(
								true,
								$"Directory traversal vulnerability detected at {url}. Content preview:\n{content[..Math.Min(content.Length, 500)]}",
								targetIp,
								AffectedService: "HTTP",
								Recommendation: "Review access controls and secure sensitive files.",
								Severity
							);
						}
					}
				}

				return new ScanResult(false, "No directory traversal vulnerabilities detected.", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Low);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"Error during directory traversal scan: {ex.Message}", targetIp);
			}
		}
	}
}
