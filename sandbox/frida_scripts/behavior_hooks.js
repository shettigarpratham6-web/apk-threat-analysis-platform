/* Frida dynamic instrumentation hooks for Android APK runtime threat monitoring */

Java.perform(function () {
    console.log("[FRIDA SCRIPT] Loaded comprehensive Android threat instrumentation hooks.");

    // Helper to send structured JSON events back to Python FridaMonitor
    function logBehaviorEvent(category, api, argsArray, extraDetails) {
        send({
            type: "behavior_event",
            category: category,
            api: api,
            args: argsArray || [],
            details: extraDetails || {},
            timestamp: Date.now()
        });
    }

    // 1. File Activity Monitoring (FileOutputStream & FileInputStream)
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (path) {
            logBehaviorEvent("file_activity", "java.io.FileOutputStream.<init>", [path.toString()]);
            return this.$init(path);
        };
        FileOutputStream.$init.overload("java.io.File").implementation = function (file) {
            var fPath = file ? file.getAbsolutePath().toString() : "";
            logBehaviorEvent("file_activity", "java.io.FileOutputStream.<init>", [fPath]);
            return this.$init(file);
        };
    } catch (err) {
        console.log("[FRIDA HOOK] FileOutputStream hook skipped: " + err);
    }

    try {
        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function (path) {
            logBehaviorEvent("file_activity", "java.io.FileInputStream.<init>", [path.toString()]);
            return this.$init(path);
        };
        FileInputStream.$init.overload("java.io.File").implementation = function (file) {
            var fPath = file ? file.getAbsolutePath().toString() : "";
            logBehaviorEvent("file_activity", "java.io.FileInputStream.<init>", [fPath]);
            return this.$init(file);
        };
    } catch (err) {
        console.log("[FRIDA HOOK] FileInputStream hook skipped: " + err);
    }

    // 2. SMS Monitoring & Interception (SmsManager)
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (destinationAddress, scAddress, text, sentIntent, deliveryIntent) {
            var dest = destinationAddress ? destinationAddress.toString() : "";
            var body = text ? text.toString() : "";
            logBehaviorEvent("sms_interception", "SmsManager.sendTextMessage", [dest, body.substring(0, 50)], {
                destination: dest,
                snippet: body.substring(0, 50),
                length: body.length
            });
            return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
        };
    } catch (err) {
        console.log("[FRIDA HOOK] SmsManager hook skipped: " + err);
    }

    // 3. Process Execution & Shell Commands (Runtime.exec & ProcessBuilder)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            var commandStr = cmd ? cmd.toString() : "";
            logBehaviorEvent("process_execution", "java.lang.Runtime.exec", [commandStr], { command: commandStr });
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var commandStr = cmdArray ? cmdArray.join(" ") : "";
            logBehaviorEvent("process_execution", "java.lang.Runtime.exec", [commandStr], { command: commandStr });
            return this.exec(cmdArray);
        };
    } catch (err) {
        console.log("[FRIDA HOOK] Runtime.exec hook skipped: " + err);
    }

    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmdList = this.command();
            var cmdStr = cmdList ? cmdList.toString() : "";
            logBehaviorEvent("process_execution", "ProcessBuilder.start", [cmdStr], { command: cmdStr });
            return this.start();
        };
    } catch (err) {
        console.log("[FRIDA HOOK] ProcessBuilder hook skipped: " + err);
    }

    // 4. Dynamic Code Loading (DexClassLoader & InMemoryDexClassLoader)
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optDir, libPath, parent) {
            var dPath = dexPath ? dexPath.toString() : "";
            logBehaviorEvent("dynamic_dex_load", "dalvik.system.DexClassLoader.<init>", [dPath], { dexPath: dPath });
            return this.$init(dexPath, optDir, libPath, parent);
        };
    } catch (err) {
        console.log("[FRIDA HOOK] DexClassLoader hook skipped: " + err);
    }

    // 5. Device Identification & Surveillance (TelephonyManager)
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
        console.log("[FRIDA HOOK] TelephonyManager hook skipped: " + err);
    }

    // 6. Network Connections (URL & HttpURLConnection)
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var urlString = this.toString();
            logBehaviorEvent("api_calls", "java.net.URL.openConnection", [urlString], { url: urlString });
            return this.openConnection();
        };
    } catch (err) {
        console.log("[FRIDA HOOK] URL.openConnection hook skipped: " + err);
    }

    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function () {
            try {
                var urlObj = this.getURL();
                var uStr = urlObj ? urlObj.toString() : "";
                logBehaviorEvent("api_calls", "java.net.HttpURLConnection.connect", [uStr], { url: uStr });
            } catch (_) {}
            return this.connect();
        };
    } catch (err) {
        console.log("[FRIDA HOOK] HttpURLConnection.connect hook skipped: " + err);
    }
});
