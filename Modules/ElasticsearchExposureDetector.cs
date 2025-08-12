using System;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class ElasticsearchExposureDetector : IScanModule
	{
		public string Name => "Elasticsearch Exposure Detector";
		public string Description => "Detects publicly accessible Elasticsearch instances without authentication.";
		public ScanSeverity Severity => ScanSeverity.High;
		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var response = await client.GetAsync($"http://{targetIp}:9200/");

				if (response.IsSuccessStatusCode)
				{
					var content = await response.Content.ReadAsStringAsync();
					if (content.Contains("\"cluster_name\"") && content.Contains("\"version\""))
					{
						return new ScanResult(
							true,
							"Publicly accessible Elasticsearch instance detected without authentication.",
							targetIp,
							AffectedService: "Elasticsearch",
							Recommendation: "Restrict access to Elasticsearch instances and enable authentication.",
							Severity: ScanSeverity.High
						);
					}
				}
				return new ScanResult(
					false,
					"No publicly accessible Elasticsearch instance detected.",
					targetIp
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false, 
					$"Error during Elasticsearch exposure scan: {ex.Message}", 
					targetIp
				);
			}
		}
	}
}
