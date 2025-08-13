using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	internal class KubernetesApiExposureDetector : IScanModule
	{
		public string Name => "Kubernetes API Exposure Detector";
		public string Description => "Detects if the Kubernetes API is exposed to the internet without proper authentication or authorization.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var response = await client.GetAsync($"https://{targetIp}:6443/api/v1/namespaces");

				var url = $"https://{targetIp}:8080/api";
				if (response.IsSuccessStatusCode)
				{
					var content = await response.Content.ReadAsStringAsync();
					if (!string.IsNullOrEmpty(content))
					{
						return new ScanResult(
							true,
							"Kubernetes API is exposed without proper authentication.",
							targetIp,
							AffectedService: "Kubernetes API",
							Recommendation: "Secure the Kubernetes API with proper authentication and authorization.",
							Severity: ScanSeverity.Critical,
							Vulnerability: "Kubernetes API Exposure"
						);
					}
				}
				return new ScanResult(
					false,
					"Kubernetes API is not exposed or requires authentication.",
					targetIp,
					AffectedService: "Kubernetes API",
					Recommendation: "Ensure Kubernetes API is secured and not publicly accessible.",
					Severity: ScanSeverity.Critical
				);
			}
			catch ( Exception ex )
			{
				return new ScanResult(
					false,
					$"Kubernetes API exposure detection failed: {ex.Message}",
					targetIp,
					AffectedService: "Kubernetes API",
					Recommendation: "Check Kubernetes API configuration and ensure it is not exposed to the internet.",
					Severity: ScanSeverity.Critical
				);
			}
		}
	}
}
