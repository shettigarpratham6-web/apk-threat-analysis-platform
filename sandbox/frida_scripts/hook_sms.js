/**
 * hook_sms.js - Android SMS Monitoring & Interception Hook
 * Monitors SmsManager.sendTextMessage() passively.
 * Does NOT transmit real SMS messages; purely observational.
 */

Java.perform(function () {
    console.log("[*] [Frida] SMS monitoring hook initialized (Passive Observation).");

    function sendEvent(eventType, details) {
        var event = {
            timestamp: new Date().toISOString(),
            module: "sms",
            type: eventType,
            pid: Process.id,
            details: details
        };
        send(JSON.stringify(event));
        console.log("[!] [SMS-INTERCEPT] " + eventType + ": " + JSON.stringify(details));
    }

    try {
        var SmsManager = Java.use("android.telephony.SmsManager");

        // Overload 1: 5 parameters (destinationAddress, scAddress, text, sentIntent, deliveryIntent)
        SmsManager.sendTextMessage.overload(
            "java.lang.String",
            "java.lang.String",
            "java.lang.String",
            "android.app.PendingIntent",
            "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sentIntent, deliveryIntent) {
            sendEvent("SMS_SEND_ATTEMPT", {
                destination: dest,
                serviceCenter: sc,
                messageLength: text ? text.length : 0,
                messageSnippet: text ? (text.length > 30 ? text.substring(0, 30) + "..." : text) : "",
                blocked: false,
                is_monitoring_only: true
            });

            // Call original to keep behavior transparent or allow analysis observation
            return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent);
        };

        // Overload 2: 7 parameters with messageId/priority if present on newer APIs
        try {
            SmsManager.sendTextMessage.overload(
                "java.lang.String",
                "java.lang.String",
                "java.lang.String",
                "android.app.PendingIntent",
                "android.app.PendingIntent",
                "long"
            ).implementation = function (dest, sc, text, sentIntent, deliveryIntent, messageId) {
                sendEvent("SMS_SEND_ATTEMPT_V2", {
                    destination: dest,
                    serviceCenter: sc,
                    messageLength: text ? text.length : 0,
                    messageId: messageId.toString(),
                    is_monitoring_only: true
                });
                return this.sendTextMessage(dest, sc, text, sentIntent, deliveryIntent, messageId);
            };
        } catch (e2) {}

    } catch (e) {
        console.error("[-] Hook error in SmsManager: " + e.message);
    }
});
