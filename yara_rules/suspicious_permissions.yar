rule Suspicious_SMS_And_Boot_Permissions
{
    meta:
        description = "Detects combined SMS and boot receiver permission indicators"
        author = "APK Threat Analysis Platform"
        severity = "MEDIUM"
    strings:
        $sms1 = "android.permission.SEND_SMS" ascii wide
        $sms2 = "android.permission.RECEIVE_SMS" ascii wide
        $boot = "android.intent.action.BOOT_COMPLETED" ascii wide
        $admin = "android.app.action.DEVICE_ADMIN_ENABLED" ascii wide
    condition:
        ($sms1 or $sms2) and ($boot or $admin)
}
