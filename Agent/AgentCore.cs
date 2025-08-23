using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace AetherSec.Agent
{
	public class AgentCore
	{
		public static void Main(string[] args)
		{
			AgentSettings.Load();
			SystemInfoCollector.Collect();
			VulnerabilityScanner.RunScans();
			ReportSender.SendToController();
			if (AgentSettings.SelfDestruct) SelfDestruct.Setup();
		}
	}
	public static class AgentSettings
	{
		public static string ControllerIp { get; private set; } = "192.168.0.100";
		public static bool SelfDestruct { get; private set; } = false;

		public static void Load()
		{
			// In future: load from encrypted JSON or secure input
			Console.WriteLine("[Settings] Loaded default settings.");
		}
	}
	public static class SystemInfoCollector
	{
		public static Dictionary<string, string> Data = new();

		public static void Collect()
		{
			Data["Hostname"] = Environment.MachineName;
			Data["OS"] = Environment.OSVersion.ToString();
			Data["Uptime"] = (DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount)).ToString();

			// Optional: Use TcpListener to check basic ports (e.g., 21, 22, 80, 443)
			Console.WriteLine("[SystemInfo] Collected system data.");
		}
	}
	public static class VulnerabilityScanner
	{
		public static List<string> Findings = new();

		public static void RunScans()
		{
			// Placeholder: Check for open SMB port as an example
			if (IsPortOpen("127.0.0.1", 445)) Findings.Add("SMB port open");

			Console.WriteLine("[Scanner] Finished vulnerability scanning.");
		}

		private static bool IsPortOpen(string ip, int port)
		{
			try
			{
				using TcpClient client = new();
				var result = client.BeginConnect(ip, port, null, null);
				return result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(500));
			}
			catch { return false; }
		}
	}
	public static class ReportSender
	{
		public static void SendToController()
		{
			var json = JsonSerializer.Serialize(new
			{
				Hostname = SystemInfoCollector.Data["Hostname"],
				OS = SystemInfoCollector.Data["OS"],
				Uptime = SystemInfoCollector.Data["Uptime"],
				Vulnerabilities = VulnerabilityScanner.Findings
			});

			using var client = new HttpClient();
			try
			{
				var response = client.PostAsync(
					$"http://{AgentSettings.ControllerIp}/api/report",
					new StringContent(json, Encoding.UTF8, "application/json")
				).Result;

				Console.WriteLine("[Report] Report sent. Status: " + response.StatusCode);
			}
			catch (Exception ex)
			{
				Console.WriteLine("[Report] Failed to send report: " + ex.Message);
			}
		}
	}
    public static class SelfDestruct
    {
        public static void Setup()
        {
            string? processPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(processPath))
            {
                Console.WriteLine("[SelfDestruct] Unable to determine process path. Self-destruct aborted.");
                return;
            }
            string exePath = processPath;
            string script = $"cmd /c timeout 10 && del \"{exePath}\"";

            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/C start /min {script}",
                WindowStyle = ProcessWindowStyle.Hidden
            });

            Console.WriteLine("[SelfDestruct] Scheduled deletion on reboot.");
        }
    }
}
