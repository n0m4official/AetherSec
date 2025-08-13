using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class JwtWeakSecretBruteForce : IScanModule
	{
		public string Name => "JWT Weak Secret Brute Force Detector";
		public string Description => "Attempts to brute force weak JWT secrets.";
		public ScanSeverity Severity => ScanSeverity.High;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var baseUrl = $"http://{targetIp}/token";
				var weakSecrets = new[] { "password", "123456", "secret", "admin" };

				foreach (var secret in weakSecrets)
				{
					var payload = JsonSerializer.Serialize(new { username = "admin", password = secret });
					var content = new StringContent(payload, Encoding.UTF8, "application/json");

					var response = await client.PostAsync(baseUrl, content);
					if (response.IsSuccessStatusCode)
					{
						var token = await response.Content.ReadAsStringAsync();
						if (!string.IsNullOrWhiteSpace(token) && token.Contains("."))
						{
							return new ScanResult(
								true,
								$"Weak JWT secret found: '{secret}'",
								targetIp,
								AffectedService: "HTTP",
								Recommendation: "Use a strong, randomly generated JWT secret.",
								Severity: ScanSeverity.High
							);
						}
					}
				}

				return new ScanResult(false, "No weak JWT secrets detected.", targetIp, AffectedService: "HTTP", Severity: ScanSeverity.Low);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"Error during JWT brute force scan: {ex.Message}", targetIp);
			}
		}
	}
}
