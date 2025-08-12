using System;
using System.Net;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class HttpsServerBannerDetector : IScanModule
	{
		public string Name => "HTTPS Server Banner Check";
		public string Description => "Checks if the HTTPS server exposes its banner information.";
		public ScanSeverity Severity => ScanSeverity.Medium;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				var request = (HttpWebRequest)WebRequest.Create($"https://{targetIp}");
				request.Method = "HEAD";
				request.Timeout = 3000;

				using var response = (HttpWebResponse)await request.GetResponseAsync();
				var serverHeader = response.Headers["Server"];

				if (!string.IsNullOrEmpty(serverHeader))
				{
					return new ScanResult(true, $"Server banner exposed: {serverHeader}", targetIp, AffectedService: "HTTPS", Severity: ScanSeverity.Medium);
				}
				else
				{
					return new ScanResult(false, "No server header disclosed.", targetIp);
				}
			}
			catch (WebException)
			{
				return new ScanResult(false, "HTTPS server not reachable or no banner.", targetIp);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"HTTPS check error: {ex.Message}", targetIp);
			}
		}
	}
}
