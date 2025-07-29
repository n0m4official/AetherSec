using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AetherSec.Core
{
	public interface IScanModule
	{
		string Name { get; }
		string Description { get; }
		ScanSeverity Severity { get; }
		ScanResult Run(string targetIp);
	}

	public enum ScanSeverity
	{
		Low,
		Medium,
		High,
		Critical
	}

	public record ScanResult(
		bool Success,
		string Message,
		string TargetIp,
		string? AffectedService = null,
		string? Recommendation = null,
		ScanSeverity Severity = ScanSeverity.Low,
		string? Vulnerability = null
		);
}
