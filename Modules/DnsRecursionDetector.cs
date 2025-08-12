using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class DnsRecursionDetector : IScanModule
	{
		public string Name => "DNS Recursion Enabled";
		public string Description => "Checks if DNS server allows recursive queries (amplification risk).";
		public ScanSeverity Severity => ScanSeverity.High;

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var udpClient = new UdpClient();
				udpClient.Client.ReceiveTimeout = 2000;
				udpClient.Connect(targetIp, 53);

				byte[] query = new byte[]
				{
					0x12, 0x34, // Transaction ID
                    0x01, 0x00, // Flags: recursion desired
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs
                    0x00, 0x00, // Authority RRs
                    0x00, 0x00, // Additional RRs
                    // Query: example.com
                    0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
					0x03, (byte)'c', (byte)'o', (byte)'m',
					0x00,       // End of name
                    0x00, 0x01, // Type: A
                    0x00, 0x01  // Class: IN
                };

				await udpClient.SendAsync(query, query.Length);

				var remoteEp = new IPEndPoint(IPAddress.Any, 0);
				var result = await udpClient.ReceiveAsync();

				byte[] response = result.Buffer;

				bool recursionAvailable = (response.Length > 3) && ((response[2] & 0x80) != 0);

				if (recursionAvailable)
				{
					return new ScanResult(
						true,
						"DNS recursion enabled — vulnerable to amplification.",
						targetIp,
						AffectedService: "DNS",
						Recommendation: "Disable recursion on DNS server if not required.",
						Severity,
						Vulnerability: "DNS Recursion Amplification"
					);
				}

				return new ScanResult(false, "DNS recursion disabled or no response.", targetIp);
			}
			catch (Exception ex)
			{
				return new ScanResult(false, $"DNS recursion check failed: {ex.Message}", targetIp);
			}
		}
	}
}
