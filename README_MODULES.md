# AetherSec Modules

This file provides a quick reference to all scan and exploit modules in AetherSec.

| Module Name | Description |
|------------|-------------|
| ApacheStrutsCVE20175638Exploit.cs | Detects and simulates the Apache Struts OGNL injection vulnerability (CVE-2017-5638). |
| BlueKeepDetector.cs | Checks if the target is vulnerable to the RDP BlueKeep (CVE-2019-0708) vulnerability. |
| ClickJackingScan.cs | Detects if web applications are susceptible to clickjacking attacks. |
| CloudMetadataExposureScan.cs | Checks cloud services for exposed metadata endpoints. |
| CmsFingerprinterScan.cs | Identifies CMS platforms used by a web target. |
| CmsPluginEnumeratorScan.cs | Enumerates plugins or modules on CMS platforms for potential vulnerabilities. |
| ConfluenceOgnlInjectionScan.cs | Simulates detection of Confluence OGNL injection vulnerabilities. |
| DirectoryTraversalDetector.cs | Checks for directory traversal vulnerabilities in web applications. |
| DnsRecursionDetector.cs | Detects DNS servers allowing recursion to unauthorized clients. |
| ElasticsearchCVE20151427RceDetector.cs | Detects Elasticsearch RCE vulnerabilities (CVE-2015-1427). |
| ElasticsearchExposureDetector.cs | Checks if Elasticsearch instances are publicly exposed. |
| EternalBlueDetector.cs | Detects SMBv1 and potential vulnerability to EternalBlue (MS17-010). |
| FtpAnonymousLoginDetector.cs | Checks if FTP servers allow anonymous login. |
| FtpAnonymousScan.cs | Scans for anonymous-accessible FTP directories. |
| HeartbleedDetector.cs | Checks OpenSSL implementations for Heartbleed (CVE-2014-0160). |
| HoneypotDetector.cs | Attempts to detect honeypots or deceptive security traps. |
| HttpsServerBannerDetector.cs | Retrieves and analyzes HTTPS server banners for version information. |
| JenkinsPanelExploit.cs | Detects publicly accessible Jenkins panels and weak authentication. |
| JwtWeakSecretBruteForce.cs | Attempts brute-force attacks against JWT tokens using common secrets. |
| KubernetesApiExposureDetector.cs | Detects publicly exposed Kubernetes API endpoints. |
| KubernetesDashboardUnauthAccessDetector.cs | Checks if Kubernetes Dashboard can be accessed without authentication. |
