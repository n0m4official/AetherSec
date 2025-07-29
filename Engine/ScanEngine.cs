using AetherSec.Core;
using AetherSec.Modules;
using AetherSec.Logging;

namespace AetherSec.Engine
{
	public class ScanEngine
	{
		private readonly List<IScanModule> _modules;

		public ScanEngine()
		{
			_modules = ModuleLoader.LoadAllModules();
		}

		public void RunScan(string targetIp)
		{
			Console.WriteLine($"\nScanning: {targetIp}\n");
			foreach (var module in _modules)
			{
				var result = module.Run(targetIp);
				ReportLogger.Log(result, module);
			}
		}
	}
}
