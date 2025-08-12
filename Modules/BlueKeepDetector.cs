using System;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class BlueKeepDetector : IScanModule
	{
		public string Name => "BlueKeep RDP Vulnerability Detector";
		public string Description => "Detects the BlueKeep vulnerability (CVE-2019-0708) in RDP services.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			const int port = 3389;
			try
			{
				using var client = new TcpClient();
				var connectTask = client.ConnectAsync(targetIp, port);
				var timeoutTask = Task.Delay(3000);

				var completedTask = await Task.WhenAny(connectTask, timeoutTask);
				if (completedTask == timeoutTask || !client.Connected)
				{
					return new ScanResult(
						false,
						"RDP port is closed or unreachable.",
						targetIp,
						AffectedService: "RDP",
						Recommendation: "Ensure RDP port 3389 is accessible and not firewalled.",
						Severity: ScanSeverity.High,
						Vulnerability: "CVE-2019-0708"
					);
				}

				using NetworkStream stream = client.GetStream();

				byte[] connectionRequest =
				{
					0x03, 0x00, 0x00, 0x13,
					0x0E, 0xE0, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x01,
					0x00, 0x00, 0x03, 0x00
				};

				// Write the connection request asynchronously
				await stream.WriteAsync(connectionRequest, 0, connectionRequest.Length);
				await stream.FlushAsync();

				var response = new byte[11];
				int bytesRead = 0;
				while (bytesRead < 11)
				{
					int read = await stream.ReadAsync(response, bytesRead, 11 - bytesRead);
					if (read == 0)
						break; // Connection closed unexpectedly
					bytesRead += read;
				}

				if (bytesRead < 11)
				{
					return new ScanResult(
						false,
						"Failed to read enough data from RDP service.",
						targetIp,
						AffectedService: "RDP",
						Recommendation: "Check RDP service status.",
						Severity: ScanSeverity.Critical,
						Vulnerability: "CVE-2019-0708"
					);
				}

				// Check response byte at position 5 per original logic
				return response[5] switch
				{
					0xD0 => new ScanResult(
						true,
						"RDP is accessible. Target might be vulnerable to BlueKeep if unpatched.",
						targetIp,
						AffectedService: "RDP",
						Recommendation: "Patch Windows systems with latest security updates.",
						Severity: ScanSeverity.Critical,
						Vulnerability: "CVE-2019-0708"
					),
					0xF0 => new ScanResult(
						false,
						"RDP refused the connection — likely patched or restricted.",
						targetIp,
						AffectedService: "RDP",
						Severity: ScanSeverity.Low
					),
					_ => new ScanResult(
						false,
						"RDP responded, but the format was unrecognized.",
						targetIp,
						AffectedService: "RDP",
						Severity: ScanSeverity.Low
					)
				};
			}
			catch (SocketException se)
			{
				return new ScanResult(
					false,
					$"Socket error: {se.Message}",
					targetIp,
					AffectedService: "RDP",
					Recommendation: "Check network connectivity and firewall settings.",
					Severity: ScanSeverity.High
				);
			}
			catch (IOException ioEx)
			{
				return new ScanResult(
					false,
					$"I/O error: {ioEx.Message}",
					targetIp,
					AffectedService: "RDP",
					Recommendation: "Ensure RDP service is running and accessible.",
					Severity: ScanSeverity.High
				);
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false,
					$"Unexpected error: {ex.Message}",
					targetIp,
					AffectedService: "RDP",
					Recommendation: "Review logs for more details.",
					Severity: ScanSeverity.Critical
				);
			}
		}
	}
}
