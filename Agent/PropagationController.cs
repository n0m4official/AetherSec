using AetherSec.Agent.Propagation;

namespace AetherSec.Agent.Propagation
{
	public class PropagationController
	{
		private readonly PropagationConfig config;
		private readonly PropagationService service;

		public PropagationController(PropagationConfig config, PropagationService service)
		{
			this.config = config;
			this.service = service;
		}

		public async Task RunPropagationAsync(IEnumerable<string> discoveredHosts, string username, string password)
		{
			var tasks = new List<Task>();

			foreach (var host in discoveredHosts)
			{
				if (!config.IsHostAllowed(host))
				{
					Console.WriteLine($"[-] Skipping {host} - not allowed by config.");
					continue;
				}

				if (tasks.Count >= config.MaxConcurrentPropagations)
				{
					break;
				}

				tasks.Add(service.AttemptPropagationAsync(host, username, password));
			}

			await Task.WhenAll(tasks);
		}
	}
}
