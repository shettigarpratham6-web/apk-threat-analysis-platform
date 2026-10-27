/**
 * hook_network.js - Android Network API Monitoring Hook
 * Intercepts java.net.URL, HttpURLConnection, and Socket connections.
 * Outputs structured JSON events for forensic correlation.
 */

Java.perform(function () {
    console.log("[*] [Frida] Network monitoring hook initialized.");

    function sendEvent(eventType, details) {
        var event = {
            timestamp: new Date().toISOString(),
            module: "network",
            type: eventType,
            pid: Process.id,
            details: details
        };
        send(JSON.stringify(event));
        console.log("[+] [NETWORK] " + eventType + ": " + JSON.stringify(details));
    }

    try {
        // Hook 1: java.net.URL.openConnection()
        var URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            var urlString = this.toString();
            sendEvent("URL_OPEN_CONNECTION", {
                url: urlString,
                protocol: this.getProtocol(),
                host: this.getHost(),
                port: this.getPort()
            });
            return this.openConnection();
        };

        URL.openConnection.overload("java.net.Proxy").implementation = function (proxy) {
            var urlString = this.toString();
            sendEvent("URL_OPEN_CONNECTION_PROXY", {
                url: urlString,
                proxy: proxy ? proxy.toString() : "DIRECT"
            });
            return this.openConnection(proxy);
        };
    } catch (e) {
        console.error("[-] Hook error in URL.openConnection: " + e.message);
    }

    try {
        // Hook 2: java.net.HttpURLConnection.connect()
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.connect.implementation = function () {
            try {
                var urlObj = this.getURL();
                sendEvent("HTTP_CONNECT", {
                    url: urlObj ? urlObj.toString() : "UNKNOWN",
                    method: this.getRequestMethod()
                });
            } catch (err) {
                console.error("[-] Error extracting connect details: " + err.message);
            }
            return this.connect();
        };
    } catch (e) {
        console.error("[-] Hook error in HttpURLConnection: " + e.message);
    }

    try {
        // Hook 3: java.net.Socket.connect()
        var Socket = Java.use("java.net.Socket");
        var SocketAddress = Java.use("java.net.SocketAddress");
        var InetSocketAddress = Java.use("java.net.InetSocketAddress");

        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (endpoint, timeout) {
            try {
                var isa = Java.cast(endpoint, InetSocketAddress);
                sendEvent("SOCKET_CONNECT", {
                    host: isa.getHostString(),
                    address: isa.getAddress() ? isa.getAddress().getHostAddress() : null,
                    port: isa.getPort(),
                    timeout_ms: timeout
                });
            } catch (err) {
                sendEvent("SOCKET_CONNECT", {
                    raw_endpoint: endpoint ? endpoint.toString() : "UNKNOWN",
                    timeout_ms: timeout
                });
            }
            return this.connect(endpoint, timeout);
        };
    } catch (e) {
        console.error("[-] Hook error in Socket.connect: " + e.message);
    }

    try {
        // Hook 4: OkHttpClient (if present in target app)
        var RealCall = Java.use("okhttp3.RealCall");
        RealCall.execute.implementation = function () {
            try {
                var req = this.request();
                sendEvent("OKHTTP_EXECUTE", {
                    url: req.url().toString(),
                    method: req.method()
                });
            } catch (err) {}
            return this.execute();
        };
    } catch (e) {
        // OkHttp might not be bundled in all apps; non-fatal
    }
});
