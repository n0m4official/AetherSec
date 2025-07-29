using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AetherSec.Engine;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.CLI
{
	class Program
	{
		static void Main(string[] args)
		{
			Console.Title = "AetherSec - Ethical Network Vulnerability Scanner";

			Console.WriteLine("Welcome to AetherSec!");
			Console.WriteLine("Enter the target IP or subnet: ");
			var target = Console.ReadLine();

			var engine = new ScanEngine();
			engine.RunScan(target);
		}
	}
}
