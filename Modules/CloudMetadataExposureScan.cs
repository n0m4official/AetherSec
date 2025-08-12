using System;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class CloudMetadataExposureScan : IScanModule
	{
		public string Name => "Cloud Metadata Exposure Scanner";
		public string Description => "Detects if cloud metadata endpoints (AWS, GCP, Azure) are accessible via proxy misconfiguration.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
				var request = new HttpRequestMessage(HttpMethod.Get, $"http://{targetIp}/latest/meta-data/");
				request.Headers.Host = "169.254.169.254"; // Cloud metadata IP spoofing

				var response = await client.SendAsync(request);

				if (response.IsSuccessStatusCode)
				{
					var content = await response.Content.ReadAsStringAsync();

					if (!string.IsNullOrWhiteSpace(content) &&
						(content.Contains("iam/") || content.Contains("instance-id")))
					{
						return new ScanResult(
							true,
							"Cloud metadata endpoint is exposed via host header injection!",
							targetIp,
							AffectedService: "HTTP",
							Recommendation: "Fix proxy configuration to block host header injection.",
							Severity
						);
					}
				}

				return new ScanResult(
					false,
					"Cloud metadata endpoint is not accessible via proxy headers.",
					targetIp,
					AffectedService: "HTTP",
					Severity: ScanSeverity.Low
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false,
					$"Cloud metadata check failed: {ex.Message}",
					targetIp,
					AffectedService: "HTTP",
					Recommendation: "Check proxy and network configurations.",
					Severity
				);
			}
		}
	}
}
