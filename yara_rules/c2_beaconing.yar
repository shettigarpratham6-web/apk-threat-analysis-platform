rule Suspicious_C2_Beaconing
{
    meta:
        description = "Detects hardcoded Command and Control endpoints and suspicious HTTP traffic patterns"
        author = "APK Threat Analysis Platform"
        severity = "HIGH"
    strings:
        $c2_domain1 = "threat-c2.com" ascii wide
        $c2_domain2 = "c2server.org" ascii wide
        $c2_uri = "/api/v1/ping" ascii wide
    condition:
        any of ($c2_domain*, $c2_uri)
}
