using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class KubernetesDashboardUnauthAccessDetector : IScanModule
	{
		public string Name => "Kubernetes Dashboard Unauthenticated Access Detector";
		public string Description => "Detects unauthenticated access to Kubernetes Dashboard.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var url = $"http://{targetIp}:8001/api/v1/namespaces/kube-system/services/https:kubernets-dashboard:/proxy/";

				var response = await client.GetAsync(url);
				if (response.IsSuccessStatusCode)
				{
					var content = await response.Content.ReadAsStringAsync();
					if (!string.IsNullOrWhiteSpace(content) && content.Contains("Kubernetes Dashboard"))
					{
						return new ScanResult(
							true,
							$"Unauthenticated Kubernetes Dashboard access detected at {url}.",
							targetIp,
							AffectedService: "Kubernetes Dashboard",
							Recommendation: "Require authentication and limit dashboard access to trusted networks.",
							Severity: ScanSeverity.Critical
						);
					}
				}
				return new ScanResult(
					false,
					"No unauthenticated Kubernetes Dashboard access detected.", 
					targetIp, 
					AffectedService: "Kubernetes Dashboard", 
					Severity: ScanSeverity.Low
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"Error during Kubernetes Dashboard access scan: {ex.Message}", targetIp);
			}
		}
	}
}
