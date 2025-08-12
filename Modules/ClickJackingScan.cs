using System;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class ClickJackingScan : IScanModule
	{
		public string Name => "Clickjacking Vulnerability Scanner";
		public string Description => "Detects potential clickjacking vulnerabilities by checking the X-Frame-Options header.";
		public ScanSeverity Severity => ScanSeverity.Medium;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var response = await client.GetAsync($"http://{targetIp}");

				if (!response.Headers.Contains("X-Frame-Options"))
				{
					return new ScanResult(
						true,
						"Target is vulnerable to clickjacking (X-Frame-Options header not set).",
						targetIp,
						AffectedService: "HTTP",
						Recommendation: "Add and correctly configure the X-Frame-Options header.",
						Severity
					);
				}

				var header = string.Join(",", response.Headers.GetValues("X-Frame-Options")).ToLowerInvariant();

				if (header != "deny" && header != "sameorigin")
				{
					return new ScanResult(
						true,
						"Target has X-Frame-Options header, but with unrecognized value. May be misconfigured.",
						targetIp,
						AffectedService: "HTTP",
						Recommendation: "Set X-Frame-Options header to 'deny' or 'sameorigin'.",
						Severity
					);
				}

				return new ScanResult(
					false,
					"X-Frame-Options header is present and correctly set.",
					targetIp,
					AffectedService: "HTTP",
					Severity: ScanSeverity.Low
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false,
					$"Clickjacking detection error: {ex.Message}",
					targetIp,
					AffectedService: "HTTP",
					Recommendation: "Check network connectivity and server configuration.",
					Severity
				);
			}
		}
	}
}
