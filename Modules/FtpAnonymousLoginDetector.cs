using System;
using System.Net;
using System.Net.FtpClient;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class FtpAnonymousLoginDetector : IScanModule
	{
		public string Name => "FTP Anonymous Login Detector";
		public string Description => "Checks if FTP server allows anonymous login.";
		public ScanSeverity Severity => ScanSeverity.Medium;
		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				#pragma warning disable SYSLIB0014
				var request = (FtpWebRequest)WebRequest.Create($"ftp://{targetIp}/");
				#pragma warning restore SYSLIB0014

				request.Method = WebRequestMethods.Ftp.ListDirectory;
				request.Credentials = new NetworkCredential("anonymous", "anonymour@domain.com");
				request.Timeout = 3000;

				using var response = (FtpWebResponse)await request.GetResponseAsync();

				return new ScanResult(
					true,
					"FTP server allows anonymous login.",
					targetIp,
					AffectedService: "FTP",
					Recommendation: "Disable anonymous login to enhance security.",
					Severity: ScanSeverity.Medium
				);
			}
			catch (WebException ex)
			{
				if (ex.Response is FtpWebResponse ftpResponse && ftpResponse.StatusCode == FtpStatusCode.NotLoggedIn)
				{
					return new ScanResult(
						false,
						"FTP server does not allow anonymous login.",
						targetIp
					);
				}
				return new ScanResult(
					false,
					$"FTP request failed: {ex.Message}",
					targetIp
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false,
					$"Unexpected error: {ex.Message}",
					targetIp
				);
			}
		}
	}
}
