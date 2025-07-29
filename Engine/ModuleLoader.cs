using AetherSec.Core;
using System.Reflection;

namespace AetherSec.Modules
{
	public static class ModuleLoader
	{
		public static List<IScanModule> LoadAllModules()
		{
			var modules = new List<IScanModule>();
			var types = Assembly.GetExecutingAssembly()
				.GetTypes()
				.Where(t => typeof(IScanModule).IsAssignableFrom(t) && !t.IsInterface);

			foreach (var type in types)
			{
				if (Activator.CreateInstance(type) is IScanModule module)
				{
					modules.Add(module);
				}
			}

			return modules;
		}
	}
}
