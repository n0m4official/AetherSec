using System;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class HoneypotDetector : IScanModule
	{
		public string Name => "Honeypot Detection";
		public string Description => "Detects if the target is a honeypot by checking for common honeypot signatures and behaviors.";
		public ScanSeverity Severity => ScanSeverity.Low;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
				var response = await client.GetAsync($"http://{targetIp}/");

				string serverHeader = response.Headers.Server?.ToString() ?? string.Empty;
				string headersString = response.Headers.ToString();

				if (serverHeader.ToLower().Contains("hhoneypot") ||
					headersString.ToLower().Contains("canarytoken") ||
					serverHeader.ToLower().Contains("cowrie") ||
					serverHeader.ToLower().Contains("dionaea"))
				{
					return new ScanResult(false, "Honeypot detected based on server headers.", targetIp, Severity: ScanSeverity.Low);
				}
			}
			catch (HttpRequestException ex)
			{
				if (ex.Message.ToLower().Contains("connection reset"))
				{
					return new ScanResult(true, "Possible honeypot behavior: connection forcibly reset.", targetIp, Severity: ScanSeverity.Low);
				}
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"Honeypot detection failed: {ex.Message}", targetIp);
			}

			return new ScanResult(false, "No signs of honeypot behavior detected.", targetIp);
		}
	}
}
