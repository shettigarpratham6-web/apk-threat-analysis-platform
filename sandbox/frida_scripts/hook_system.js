/**
 * hook_system.js - System API, Process Execution & File Access Monitor
 * Tracks java.lang.Runtime.exec, ProcessBuilder, DexClassLoader, and sensitive file operations.
 */

Java.perform(function () {
    console.log("[*] [Frida] System behavior hook initialized.");

    function sendEvent(eventType, details) {
        var event = {
            timestamp: new Date().toISOString(),
            module: "system",
            type: eventType,
            pid: Process.id,
            details: details
        };
        send(JSON.stringify(event));
        console.log("[+] [SYSTEM] " + eventType + ": " + JSON.stringify(details));
    }

    // 1. Process Execution Monitoring (Runtime.exec)
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            sendEvent("PROCESS_EXEC", { command: cmd });
            return this.exec(cmd);
        };

        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
            var fullCmd = cmdArray ? cmdArray.join(" ") : "";
            sendEvent("PROCESS_EXEC_ARRAY", { command: fullCmd });
            return this.exec(cmdArray);
        };
    } catch (e) {
        console.error("[-] Hook error in Runtime.exec: " + e.message);
    }

    // 2. ProcessBuilder Monitoring
    try {
        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            var cmdList = this.command();
            var cmdStr = cmdList ? cmdList.toString() : "UNKNOWN";
            sendEvent("PROCESS_BUILDER_START", { command: cmdStr });
            return this.start();
        };
    } catch (e) {
        console.error("[-] Hook error in ProcessBuilder: " + e.message);
    }

    // 3. Dynamic Code Loading (DexClassLoader)
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (dexPath, optDir, libSearchPath, parent) {
            sendEvent("DYNAMIC_DEX_LOAD", {
                dexPath: dexPath,
                optimizedDirectory: optDir,
                librarySearchPath: libSearchPath
            });
            return this.$init(dexPath, optDir, libSearchPath, parent);
        };
    } catch (e) {
        console.error("[-] Hook error in DexClassLoader: " + e.message);
    }

    // 4. File Access to Sensitive Paths
    try {
        var File = Java.use("java.io.File");
        File.$init.overload("java.lang.String").implementation = function (path) {
            if (path && (path.indexOf("/system/") === 0 || path.indexOf("/data/data/") === 0 || path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1)) {
                sendEvent("SENSITIVE_FILE_ACCESS", { path: path });
            }
            return this.$init(path);
        };
    } catch (e) {
        console.error("[-] Hook error in File constructor: " + e.message);
    }
});
