using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AetherSec.Agent.Propagation
{
    public class PropagationController
    {
        private readonly PropagationConfig config;
        private readonly PropagationService service;
        private readonly SemaphoreSlim semaphore;

        public PropagationController(PropagationConfig config, PropagationService service)
        {
            this.config = config;
            this.service = service;
            this.semaphore = new SemaphoreSlim(config.MaxConcurrentPropagations);
        }

        public async Task RunPropagationAsync(List<string> targetHosts, string username = "", string password = "")
        {
            if (!config.EnablePropagation)
            {
                Console.WriteLine("[!] Propagation is disabled in config.");
                return;
            }

            var tasks = new List<Task>();

            foreach (var host in targetHosts)
            {
                // Skip hosts not allowed by whitelist/blacklist
                if (!config.IsHostAllowed(host))
                {
                    Console.WriteLine($"[-] Skipping {host} (not allowed by config).");
                    continue;
                }

                await semaphore.WaitAsync();

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        bool success = await service.AttemptPropagationAsync(host, username, password);
                        if (success)
                        {
                            Console.WriteLine($"[+] Propagation succeeded: {host}");
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);
            Console.WriteLine("[*] Propagation run complete.");
        }
    }
}
