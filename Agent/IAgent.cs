namespace AetherSec.Agent
{
	public interface IAgent
	{
		string HostId { get; }
		string CurrentIp { get; }
		Task StartAsync();
		Task ScanAndPropagateAsync();
		Task ReportFindingsAsync();
	}
}
