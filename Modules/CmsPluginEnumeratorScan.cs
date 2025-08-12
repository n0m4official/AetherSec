using AetherSec.Core;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace AetherSec.Modules
{
	public class CmsPluginEnumeratorScan : IScanModule
	{
		public string Name => "CMS Plugin Version Enumerator";
		public string Description => "Attempts to enumerate CMS plugins and their versions from common file paths.";
		public ScanSeverity Severity => ScanSeverity.Medium;

		private readonly string[] _commonCmsPaths =
		{
			"/wp-includes/version.php",                // WordPress
            "/readme.html",                            // WordPress or Joomla
            "/administrator/manifests/files/joomla.xml", // Joomla
            "/CHANGELOG.txt",                          // Drupal
            "/core/COPYRIGHT.txt"                      // Drupal
        };

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

				foreach (var path in _commonCmsPaths)
				{
					var url = $"http://{targetIp}{path}";
					var response = await client.GetAsync(url);

					if (response.IsSuccessStatusCode)
					{
						var content = await response.Content.ReadAsStringAsync();

						if (!string.IsNullOrWhiteSpace(content) &&
							(content.Contains("wordpress", StringComparison.OrdinalIgnoreCase) ||
							 content.Contains("joomla", StringComparison.OrdinalIgnoreCase) ||
							 content.Contains("drupal", StringComparison.OrdinalIgnoreCase) ||
							 content.Contains("plugin", StringComparison.OrdinalIgnoreCase) ||
							 content.Contains("version", StringComparison.OrdinalIgnoreCase)))
						{
							return new ScanResult(
								true,
								$"Potential CMS/plugin metadata found at {url}:\n{content[..Math.Min(content.Length, 500)]}",
								targetIp,
								AffectedService: "HTTP",
								Recommendation: "Review exposed plugin/version info and secure accordingly.",
								Severity: ScanSeverity.Medium
							);
						}
					}
				}

				return new ScanResult(false, "No CMS metadata or plugin versions found in common paths.", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Medium);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"CMS plugin enumeration failed: {ex.Message}", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Medium);
			}
		}
	}
}
