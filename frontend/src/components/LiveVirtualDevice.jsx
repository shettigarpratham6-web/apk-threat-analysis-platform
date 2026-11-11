import React, { useState, useEffect, useRef } from "react";
import { getDeviceScreenUrl, getDeviceInfo, sendDeviceTouch, wakeDevice } from "../api/client";

export default function LiveVirtualDevice({ activePackageName, isRunning }) {
  const [screenUrl, setScreenUrl] = useState(getDeviceScreenUrl());
  const [deviceInfo, setDeviceInfo] = useState({ online: true, current_app: "Loading...", device: "emulator-5554" });
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [screenError, setScreenError] = useState(false);
  const [touchIndicator, setTouchIndicator] = useState(null);
  const screenRef = useRef(null);
  const streamTimerRef = useRef(null);

  // Poll device status every 4 seconds
  useEffect(() => {
    let isMounted = true;
    const fetchInfo = async () => {
      try {
        const info = await getDeviceInfo();
        if (isMounted && info) setDeviceInfo(info);
      } catch (_) {}
    };

    fetchInfo();
    const infoInterval = setInterval(fetchInfo, 4000);
    return () => {
      isMounted = false;
      clearInterval(infoInterval);
    };
  }, []);

  // Adaptive chained frame streaming (zero overlapping requests, buttery-smooth)
  const scheduleNextFrame = (delayMs = 750) => {
    if (streamTimerRef.current) clearTimeout(streamTimerRef.current);
    if (!isLiveStreaming) return;
    streamTimerRef.current = setTimeout(() => {
      setScreenUrl(getDeviceScreenUrl());
    }, delayMs);
  };

  useEffect(() => {
    if (isLiveStreaming) {
      scheduleNextFrame(100);
    }
    return () => {
      if (streamTimerRef.current) clearTimeout(streamTimerRef.current);
    };
  }, [isLiveStreaming]);

  // Force immediate refresh when analysis begins
  useEffect(() => {
    if (isRunning) {
      setIsLiveStreaming(true);
      scheduleNextFrame(150);
    }
  }, [isRunning]);

  const handleFrameLoad = () => {
    setScreenError(false);
    scheduleNextFrame(750);
  };

  const handleFrameError = () => {
    setScreenError(true);
    scheduleNextFrame(2500);
  };

  const handleScreenClick = (e) => {
    if (!screenRef.current) return;
    const rect = screenRef.current.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const relX = Math.max(0, Math.min(1, clickX / rect.width));
    const relY = Math.max(0, Math.min(1, clickY / rect.height));

    // Instant tactile feedback ripple
    setTouchIndicator({ x: clickX, y: clickY });
    setTimeout(() => setTouchIndicator(null), 350);

    // Asynchronous touch dispatch & rapid next-frame capture
    sendDeviceTouch({ action: "tap", x: relX, y: relY })
      .then(() => setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 120))
      .catch(err => console.warn("Touch error:", err));
  };

  const handleKey = (keyCode) => {
    sendDeviceTouch({ action: "key", key_code: keyCode })
      .then(() => setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 120))
      .catch(err => console.warn("Key error:", err));
  };

  const handleWake = () => {
    wakeDevice()
      .then(() => setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 150))
      .catch(() => {});
  };

  return (
    <div className="card live-phone-card" style={{
      background: "var(--card-bg)",
      border: "1px solid var(--card-border)",
      borderRadius: "0",
      padding: "20px",
      display: "flex",
      flexDirection: "column",
      alignItems: "center"
    }}>
      {/* Top Header Bar */}
      <div style={{
        width: "100%",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        marginBottom: "14px",
        flexWrap: "wrap",
        gap: "8px"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{
            display: "inline-block",
            width: "8px",
            height: "8px",
            borderRadius: "0",
            backgroundColor: isLiveStreaming ? "var(--neon-green)" : "var(--warning-amber)",
            boxShadow: isLiveStreaming ? "0 0 10px var(--neon-green)" : "none"
          }}></span>
          <span style={{ fontWeight: "900", fontSize: "13px", color: "var(--text-main)", letterSpacing: "1px", fontFamily: "var(--font-mono)" }}>
            LIVE VIRTUAL DEVICE
          </span>
          <span style={{
            background: "#050505",
            color: "var(--neon-green)",
            border: "1px solid var(--card-border)",
            padding: "2px 8px",
            borderRadius: "0",
            fontSize: "11px",
            fontFamily: "var(--font-mono)"
          }}>
            {deviceInfo.device || "emulator-5554"}
          </span>
        </div>

        <div style={{ display: "flex", gap: "6px" }}>
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className="btn btn-sm btn-secondary"
            style={{
              padding: "4px 10px",
              fontSize: "10px",
              borderRadius: "0"
            }}
          >
            {isLiveStreaming ? "🟢 LIVE (1S)" : "⏸️ PAUSED"}
          </button>
          <button
            onClick={() => { setScreenUrl(getDeviceScreenUrl()); handleWake(); }}
            className="btn btn-sm btn-secondary"
            style={{
              padding: "4px 10px",
              fontSize: "10px",
              borderRadius: "0"
            }}
          >
            ⚡ WAKE
          </button>
        </div>
      </div>

      {/* Target App Badge */}
      <div style={{
        width: "100%",
        background: "#050505",
        border: "1px solid var(--card-border)",
        padding: "8px 12px",
        borderRadius: "0",
        marginBottom: "16px",
        fontSize: "11px",
        fontFamily: "var(--font-mono)",
        color: "var(--text-muted)",
        display: "flex",
        justifyContent: "space-between"
      }}>
        <span>FOCUSED: <strong style={{ color: "var(--neon-green)" }}>{deviceInfo.current_app || activePackageName || "Home Launcher"}</strong></span>
        <span>DISPLAY: <strong style={{ color: "var(--text-main)" }}>1080×2220</strong></span>
      </div>

      {/* Realistic Smartphone Chassis */}
      <div style={{
        position: "relative",
        width: "280px",
        height: "580px",
        background: "#18181b",
        borderRadius: "36px",
        padding: "10px",
        boxShadow: "0 0 0 2px #3f3f46, 0 25px 50px -12px rgba(0, 0, 0, 0.75), inset 0 0 10px rgba(255,255,255,0.05)",
        display: "flex",
        flexDirection: "column",
        alignItems: "center"
      }}>
        {/* Top Bezel: Camera Punch-Hole & Ear Speaker */}
        <div style={{
          position: "absolute",
          top: "14px",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "4px",
          zIndex: 10
        }}>
          <div style={{ width: "40px", height: "3px", background: "#27272a", borderRadius: "2px" }}></div>
          <div style={{
            width: "10px",
            height: "10px",
            background: "#09090b",
            borderRadius: "50%",
            border: "1.5px solid #27272a"
          }}></div>
        </div>

        {/* Screen Area */}
        <div
          ref={screenRef}
          onClick={handleScreenClick}
          style={{
            position: "relative",
            width: "100%",
            height: "520px",
            borderRadius: "28px",
            overflow: "hidden",
            background: "#000",
            cursor: "crosshair",
            border: "1px solid #27272a"
          }}
          title="Click to interact with the fake mobile phone"
        >
          {screenError ? (
            <div style={{
              width: "100%",
              height: "100%",
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
              color: "#ef4444",
              padding: "20px",
              textAlign: "center"
            }}>
              <span style={{ fontSize: "36px", marginBottom: "8px" }}>📱</span>
              <p style={{ margin: 0, fontWeight: "600" }}>Device Connecting...</p>
              <button
                onClick={() => { setScreenError(false); setScreenUrl(getDeviceScreenUrl()); }}
                className="btn btn-sm btn-primary"
                style={{ marginTop: "12px", fontSize: "11px" }}
              >
                Retry Stream
              </button>
            </div>
          ) : (
            <img
              src={screenUrl}
              alt="Live Android Emulator Screen"
              onError={handleFrameError}
              onLoad={handleFrameLoad}
              style={{
                width: "100%",
                height: "100%",
                objectFit: "fill",
                userSelect: "none",
                pointerEvents: "none"
              }}
            />
          )}

          {/* Interactive Click Ripple Indicator */}
          {touchIndicator && (
            <div style={{
              position: "absolute",
              left: `${touchIndicator.x}px`,
              top: `${touchIndicator.y}px`,
              width: "24px",
              height: "24px",
              transform: "translate(-50%, -50%)",
              background: "rgba(56, 189, 248, 0.4)",
              border: "2px solid #38bdf8",
              borderRadius: "50%",
              pointerEvents: "none",
              animation: "ping 0.4s cubic-bezier(0, 0, 0.2, 1) forwards"
            }} />
          )}
        </div>

        {/* Bottom Hardware / Soft Navigation Bar */}
        <div style={{
          width: "100%",
          display: "flex",
          justifyContent: "space-around",
          alignItems: "center",
          height: "36px",
          marginTop: "auto"
        }}>
          {/* Back Button */}
          <button
            onClick={() => handleKey("4")}
            title="Back (Keyevent 4)"
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              fontSize: "14px",
              padding: "4px 12px"
            }}
          >
            ◀
          </button>

          {/* Home Button */}
          <button
            onClick={() => handleKey("3")}
            title="Home (Keyevent 3)"
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              fontSize: "15px",
              padding: "4px 12px"
            }}
          >
            ●
          </button>

          {/* Recents Button */}
          <button
            onClick={() => handleKey("187")}
            title="Recent Apps (Keyevent 187)"
            style={{
              background: "transparent",
              border: "none",
              color: "#94a3b8",
              cursor: "pointer",
              fontSize: "14px",
              padding: "4px 12px"
            }}
          >
            ◽
          </button>
        </div>
      </div>

      {/* Helpful Hint */}
      <p style={{
        margin: "12px 0 0 0",
        fontSize: "11px",
        color: "#64748b",
        textAlign: "center"
      }}>
        💡 Click on the phone screen to tap & interact in real time during analysis.
      </p>
    </div>
  );
}

