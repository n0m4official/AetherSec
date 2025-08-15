using System;
using System.IO;
using System.Threading.Tasks;

namespace AetherSec.Agent.Propagation
{
    public class PropagationService
    {
        private readonly string agentBinaryPath;
        private readonly PropagationConfig config;

        public PropagationService(PropagationConfig config, string agentBinaryPath = "AetherSecAgent.exe")
        {
            this.config = config;
            this.agentBinaryPath = agentBinaryPath;
        }

        public async Task<bool> AttemptPropagationAsync(string targetIp, string username = "", string password = "")
        {
            // Check if the host is allowed before doing anything
            if (!config.IsHostAllowed(targetIp))
            {
                Console.WriteLine($"[-] Skipping propagation to {targetIp} (not allowed by config).");
                return false;
            }

            Console.WriteLine($"[*] Attempting to propagate to {targetIp}...");

            try
            {
                if (await TrySmbDropAsync(targetIp, username, password))
                {
                    Console.WriteLine($"[+] Agent binary dropped on {targetIp}.");
                    bool execSuccess = await TriggerRemoteExecutionAsync(targetIp, username, password);

                    if (execSuccess)
                    {
                        Console.WriteLine($"[+] Remote execution successful on {targetIp}.");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"[-] Failed to execute agent on {targetIp}.");
                    }
                }
                else
                {
                    Console.WriteLine($"[-] Failed to drop file on {targetIp}.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error during propagation to {targetIp}: {ex.Message}");
            }

            return false;
        }

        private async Task<bool> TrySmbDropAsync(string targetIp, string username, string password)
        {
            Console.WriteLine($"[*] Attempting SMB file drop to {targetIp}...");

            try
            {
                // Simulated authorized lab drop
                string simulatedPath = Path.Combine(Environment.CurrentDirectory, "SimulatedDrops", targetIp.Replace('.', '_'));
                Directory.CreateDirectory(simulatedPath);
                string destFile = Path.Combine(simulatedPath, Path.GetFileName(agentBinaryPath));

                // Simulate async copy
                await Task.Run(() => File.Copy(agentBinaryPath, destFile, overwrite: true));
                await Task.Delay(100); // simulate network latency

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] SMB drop simulation failed: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> TriggerRemoteExecutionAsync(string targetIp, string username, string password)
        {
            Console.WriteLine($"[*] Triggering remote execution on {targetIp}...");

            try
            {
                // Simulate remote execution
                await Task.Delay(100); // simulate command execution latency
                Console.WriteLine($"[~] Simulated execution on {targetIp} completed.");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Remote execution simulation failed: {ex.Message}");
                return false;
            }
        }
    }
}
