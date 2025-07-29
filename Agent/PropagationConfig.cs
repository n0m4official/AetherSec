namespace AetherSec.Agent.Propagation
{
	public class PropagationConfig
	{
		public List<string> WhitelistedSubnets { get; set; } = new();
		public List<string> BlacklistedHosts { get; set; } = new();
		public bool EnablePropagation { get; set; } = true;
		public int MaxConcurrentPropagations { get; set; } = 3;
		public bool SelfDeleteOnRestart { get; set; } = true;

		public bool IsHostAllowed(string targetIp)
		{
			if (!EnablePropagation)
				return false;

			if (BlacklistedHosts.Contains(targetIp))
				return false;

			foreach (var subnet in WhitelistedSubnets)
			{
				if (targetIp.StartsWith(subnet)) // simplistic CIDR-ish check
					return true;
			}

			return false;
		}
	}
}
