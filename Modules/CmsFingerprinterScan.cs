using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class CmsFingerprinterScan : IScanModule
	{
		public string Name => "CMS Fingerprinter";
		public string Description => "Attempts to detect CMS platforms like WordPress, Joomla, or Drupal.";
		public ScanSeverity Severity => ScanSeverity.Low;

		private readonly Dictionary<string, string> _cmsPaths = new()
		{
			{ "/wp-login.php", "WordPress" },
			{ "/administrator", "Joomla" },
			{ "/core/install.php", "Drupal" },
			{ "/sites/default", "Drupal" },
			{ "/user/login", "Drupal/Joomla" },
			{ "/index.php?option=com_users", "Joomla" }
		};

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var baseUrl = $"http://{targetIp}";
				var detectedCms = new HashSet<string>();

				foreach (var entry in _cmsPaths)
				{
					var url = baseUrl + entry.Key;
					var response = await client.GetAsync(url);

					if ((int)response.StatusCode >= 200 && (int)response.StatusCode < 400)
					{
						detectedCms.Add(entry.Value);
					}
				}

				// Check headers for CMS hints
				var rootResponse = await client.GetAsync(baseUrl);
				if (rootResponse.Headers.Contains("X-Generator"))
				{
					var gen = string.Join(", ", rootResponse.Headers.GetValues("X-Generator"));
					detectedCms.Add($"Header Hint: {gen}");
				}
				if (rootResponse.Headers.Contains("X-Powered-By"))
				{
					var powered = string.Join(", ", rootResponse.Headers.GetValues("X-Powered-By"));
					detectedCms.Add($"Powered-By Hint: {powered}");
				}

				if (detectedCms.Count > 0)
				{
					var cmsList = string.Join("; ", detectedCms);
					return new ScanResult(
						true,
						$"Detected CMS platforms: {cmsList}",
						targetIp,
						AffectedService: "HTTP",
						Recommendation: "Verify and secure detected CMS platforms.",
						Severity: ScanSeverity.Low
					);
				}

				return new ScanResult(false, "No known CMS detected.", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Low);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"CMS fingerprinting error: {ex.Message}", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Low);
			}
		}
	}
}
