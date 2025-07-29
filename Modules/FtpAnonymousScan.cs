using AetherSec.Core;

namespace AetherSec.Modules
{
	public class FtpAnonymousScan : IScanModule
	{
		public string Name => "FTP Anonymous Login Scanner";
		public string Description => "Checks if FTP allows anonymous access.";
		public ScanSeverity Severity => ScanSeverity.High;

		public ScanResult Run(string targetIp)
		{
			// Placeholder logic
			bool vulnerable = targetIp.Contains("192."); // Simulated example

			return new ScanResult(
				vulnerable,
				vulnerable ? "Anonymous FTP login allowed!" : "FTP secure.",
				targetIp,
				"FTP Service",
				vulnerable ? "Disable anonymous login or restrict access." : null
			);
		}
	}
}
