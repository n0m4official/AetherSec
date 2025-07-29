using System;
using AetherSec.Core;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AetherSec.Logging
{
	public static class ReportLogger
	{
		private static readonly string ReportPath = $"report_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

		public static void Log(ScanResult result, IScanModule module)
		{
			var logEntry = new StringBuilder();
			logEntry.AppendLine($"Timestamp: {DateTime.Now}");
			logEntry.AppendLine($"Module: {module.Name}");
			logEntry.AppendLine($"Description: {module.Description}");
			logEntry.AppendLine($"Target IP: {result.TargetIp}");
			logEntry.AppendLine($"Severity: {result.Severity}");
			logEntry.AppendLine($"Success: {result.Success}");
			logEntry.AppendLine($"Message: {result.Message}");
			if (!string.IsNullOrEmpty(result.AffectedService))
				logEntry.AppendLine($"Affected Service: {result.AffectedService}");
			if (!string.IsNullOrEmpty(result.Recommendation))
				logEntry.AppendLine($"Recommendation: {result.Recommendation}");
			if (!string.IsNullOrEmpty(result.Vulnerability))
				logEntry.AppendLine($"Vulnerability: {result.Vulnerability}");
			logEntry.AppendLine(new string('-', 40));
			System.IO.File.AppendAllText(ReportPath, logEntry.ToString());
		}
	}
}
