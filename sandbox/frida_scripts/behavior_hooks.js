/* Frida dynamic instrumentation hooks for Android APK behavior monitoring */

Java.perform(function () {
    console.log("[FRIDA SCRIPT] Loaded behavior instrumentation hooks.");

    // Helper to send structured JSON events back to Python FridaMonitor
    function logBehaviorEvent(category, api, argsArray) {
        send({
            type: "behavior_event",
            category: category,
            api: api,
            args: argsArray,
            timestamp: Date.now()
        });
    }

    // 1. File Activity Hooks (FileOutputStream & FileInputStream)
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
            logBehaviorEvent("file_activity", "java.io.FileOutputStream.<init>", [path.toString()]);
            return this.$init(path);
        };
        FileOutputStream.$init.overload("java.io.File").implementation = function (file) {
            logBehaviorEvent("file_activity", "java.io.FileOutputStream.<init>", [file.getAbsolutePath().toString()]);
            return this.$init(file);
        };
    } catch (err) {
        console.log("[FRIDA HOOK WARNING] FileOutputStream hook: " + err);
    }

    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
            logBehaviorEvent("file_activity", "java.io.FileInputStream.<init>", [path.toString()]);
            return this.$init(path);
        };
        FileInputStream.$init.overload("java.io.File").implementation = function (file) {
            logBehaviorEvent("file_activity", "java.io.FileInputStream.<init>", [file.getAbsolutePath().toString()]);
            return this.$init(file);
        };
    } catch (err) {
        console.log("[FRIDA HOOK WARNING] FileInputStream hook: " + err);
    }

    // 2. SMS Sending Hooks (SmsManager)
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
            logBehaviorEvent("api_calls", "SmsManager.sendTextMessage", [
                destinationAddress ? destinationAddress.toString() : "",
                text ? text.toString() : ""
            ]);
            return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
        };
    } catch (err) {
        console.log("[FRIDA HOOK WARNING] SmsManager hook: " + err);
    }

    // 3. Device Info Hooks (TelephonyManager)
    try {
        var TelephonyManager = Java.use("android.telephony.TelephonyManager");
        if (TelephonyManager.getDeviceId) {
            TelephonyManager.getDeviceId.overload().implementation = function () {
                logBehaviorEvent("api_calls", "TelephonyManager.getDeviceId", []);
                return this.getDeviceId();
            };
        }
        if (TelephonyManager.getSubscriberId) {
            TelephonyManager.getSubscriberId.overload().implementation = function () {
                logBehaviorEvent("api_calls", "TelephonyManager.getSubscriberId", []);
                return this.getSubscriberId();
            };
        }
    } catch (err) {
        console.log("[FRIDA HOOK WARNING] TelephonyManager hook: " + err);
    }

    // 4. Network Connections Hook (URL.openConnection)
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var urlString = this.toString();
            logBehaviorEvent("api_calls", "java.net.URL.openConnection", [urlString]);
            return this.openConnection();
        };
    } catch (err) {
        console.log("[FRIDA HOOK WARNING] URL.openConnection hook: " + err);
    }
});
