using System;
using System.Threading.Tasks;
using AetherSec.Engine;

namespace AetherSec.CLI
{
	class Program
	{
		static async Task Main(string[] args)
		{
			Console.Title = "AetherSec - Ethical Network Vulnerability Scanner";

			Console.WriteLine("Welcome to AetherSec!");
			Console.WriteLine("Enter the target IP or subnet: ");
			var target = Console.ReadLine();

			var engine = new ScanEngine();
			await engine.RunScanAsync(target);

			Console.WriteLine("Scan complete. Press any key to exit.");
			Console.ReadKey();
		}
	}
}
