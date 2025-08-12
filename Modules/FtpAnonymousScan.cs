using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class FtpAnonymousScan : IScanModule
	{
		public string Name => "FTP Anonymous Login Scanner";
		public string Description => "Checks if FTP allows anonymous access.";
		public ScanSeverity Severity => ScanSeverity.High;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			const int ftpPort = 21;
			try
			{
				using var client = new TcpClient();
				var connectTask = client.ConnectAsync(targetIp, ftpPort);
				var timeoutTask = Task.Delay(5000);

				var completedTask = await Task.WhenAny(connectTask, timeoutTask);
				if (completedTask == timeoutTask || !client.Connected)
				{
					return new ScanResult(false,
						"FTP port is closed or unreachable.",
						targetIp,
						AffectedService: "FTP",
						Recommendation: "Ensure FTP port 21 is accessible.",
						Severity: ScanSeverity.Medium);
				}

				using var stream = client.GetStream();
				using var reader = new StreamReader(stream, Encoding.ASCII);
				using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

				// Read FTP server welcome message
				string welcome = await reader.ReadLineAsync();

				// Send anonymous USER command
				await writer.WriteLineAsync("USER anonymous");
				string userResponse = await reader.ReadLineAsync();

				// Send PASS command with empty password
				await writer.WriteLineAsync("PASS anonymous");
				string passResponse = await reader.ReadLineAsync();

				bool isAnonymousAllowed = userResponse.StartsWith("331") && passResponse.StartsWith("230");

				if (isAnonymousAllowed)
				{
					return new ScanResult(true,
						"Anonymous FTP login allowed!",
						targetIp,
						AffectedService: "FTP",
						Recommendation: "Disable anonymous login or restrict access.",
						Severity: ScanSeverity.High);
				}
				else
				{
					return new ScanResult(false,
						"FTP does not allow anonymous login.",
						targetIp,
						AffectedService: "FTP",
						Recommendation: "FTP server appears secure against anonymous login.",
						Severity: ScanSeverity.Low);
				}
			}
			catch (Exception ex)
			{
				return new ScanResult(false,
					$"Error during FTP anonymous login scan: {ex.Message}",
					targetIp,
					AffectedService: "FTP",
					Recommendation: "Check FTP server configuration and network accessibility.",
					Severity: ScanSeverity.Medium);
			}
		}
	}
}
