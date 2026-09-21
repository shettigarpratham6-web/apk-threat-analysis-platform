"""mitmproxy addon script to log intercepted HTTP/HTTPS traffic to a JSON lines file."""

import json
import time

try:
    from mitmproxy import ctx, http
except ImportError:
    ctx = None
    http = None


class TrafficLogger:
    """mitmproxy Addon class capturing HTTP request and response metadata."""

    def __init__(self):
        self.logfile = "network_traffic.jsonl"

    def load(self, loader):
        loader.add_option(
            name="logfile",
            typespec=str,
            default="network_traffic.jsonl",
            help="Output filepath for JSON lines traffic log",
        )

    def response(self, flow) -> None:
        if ctx and hasattr(ctx, "options"):
            self.logfile = ctx.options.logfile

        if not self.logfile:
            return

        req = flow.request
        res = flow.response

        entry = {
            "timestamp": time.time(),
            "method": req.method if req else "GET",
            "host": req.host if req else "",
            "port": req.port if req else 80,
            "path": req.path if req else "/",
            "url": req.url if req else "",
            "status_code": res.status_code if res else 0,
            "request_size": len(req.content) if req and req.content else 0,
            "response_size": len(res.content) if res and res.content else 0,
            "content_type": res.headers.get("content-type", "") if res and res.headers else "",
        }

        try:
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as err:
            if ctx:
                ctx.log.error(f"Failed to write traffic log entry: {err}")


addons = [TrafficLogger()]
