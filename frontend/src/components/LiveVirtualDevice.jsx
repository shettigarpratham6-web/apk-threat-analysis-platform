import React, { useState, useEffect, useRef } from "react";
import { getDeviceScreenUrl, getDeviceInfo, sendDeviceTouch, wakeDevice } from "../api/client";

export default function LiveVirtualDevice({ activePackageName, isRunning }) {
  const [screenUrl, setScreenUrl] = useState(getDeviceScreenUrl());
  const [deviceInfo, setDeviceInfo] = useState({ online: true, current_app: "Loading...", device: "emulator-5554" });
  const [isLiveStreaming, setIsLiveStreaming] = useState(true);
  const [screenError, setScreenError] = useState(false);
  const [touchIndicator, setTouchIndicator] = useState(null);
  const screenRef = useRef(null);

  // Poll device status
  useEffect(() => {
    let isMounted = true;
    const fetchInfo = async () => {
      try {
        const info = await getDeviceInfo();
        if (isMounted) setDeviceInfo(info);
      } catch (_) {}
    };

    fetchInfo();
    const infoInterval = setInterval(fetchInfo, 3000);
    return () => {
      isMounted = false;
      clearInterval(infoInterval);
    };
  }, []);

  // Poll live screen frames
  useEffect(() => {
    if (!isLiveStreaming) return;

    let isMounted = true;
    const interval = setInterval(() => {
      if (isMounted) {
        setScreenUrl(getDeviceScreenUrl());
      }
    }, 1000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [isLiveStreaming]);

  // Force immediate refresh on interaction or when analysis starts
  useEffect(() => {
    if (isRunning) {
      setIsLiveStreaming(true);
      const timer = setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 1200);
      return () => clearTimeout(timer);
    }
  }, [isRunning]);

  const handleScreenClick = async (e) => {
    if (!screenRef.current) return;
    const rect = screenRef.current.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const relX = Math.max(0, Math.min(1, clickX / rect.width));
    const relY = Math.max(0, Math.min(1, clickY / rect.height));

    // Display temporary touch ripple
    setTouchIndicator({ x: clickX, y: clickY });
    setTimeout(() => setTouchIndicator(null), 400);

    try {
      await sendDeviceTouch({ action: "tap", x: relX, y: relY });
      setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 300);
    } catch (err) {
      console.warn("Touch error:", err);
    }
  };

  const handleKey = async (keyCode) => {
    try {
      await sendDeviceTouch({ action: "key", key_code: keyCode });
      setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 350);
    } catch (err) {
      console.warn("Key error:", err);
    }
  };

  const handleWake = async () => {
    try {
      await wakeDevice();
      setTimeout(() => setScreenUrl(getDeviceScreenUrl()), 400);
    } catch (_) {}
  };

  return (
    <div className="card live-phone-card" style={{
      background: "linear-gradient(180deg, #0b1120 0%, #0f172a 100%)",
      border: "1px solid #1e293b",
      borderRadius: "16px",
      padding: "20px",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)"
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
            width: "10px",
            height: "10px",
            borderRadius: "50%",
            backgroundColor: isLiveStreaming ? "#22c55e" : "#eab308",
            boxShadow: isLiveStreaming ? "0 0 10px #22c55e" : "none"
          }}></span>
          <span style={{ fontWeight: "700", fontSize: "14px", color: "#f8fafc", letterSpacing: "0.5px" }}>
            LIVE VIRTUAL DEVICE
          </span>
          <span style={{
            background: "#1e293b",
            color: "#38bdf8",
            padding: "2px 8px",
            borderRadius: "4px",
            fontSize: "11px",
            fontFamily: "monospace"
          }}>
            {deviceInfo.device || "emulator-5554"}
          </span>
        </div>

        <div style={{ display: "flex", gap: "6px" }}>
          <button
            onClick={() => setIsLiveStreaming(!isLiveStreaming)}
            className="btn btn-sm"
            style={{
              padding: "4px 10px",
              fontSize: "11px",
              background: isLiveStreaming ? "#065f46" : "#334155",
              color: "#fff",
              border: "none",
              borderRadius: "4px"
            }}
          >
            {isLiveStreaming ? "🟢 Live (1s)" : "⏸️ Paused"}
          </button>
          <button
            onClick={() => { setScreenUrl(getDeviceScreenUrl()); handleWake(); }}
            className="btn btn-sm"
            style={{
              padding: "4px 10px",
              fontSize: "11px",
              background: "#334155",
              color: "#e2e8f0",
              border: "none",
              borderRadius: "4px"
            }}
          >
            ⚡ Wake Screen
          </button>
        </div>
      </div>

      {/* Target App Badge */}
      <div style={{
        width: "100%",
        background: "#0f172a",
        border: "1px solid #1e293b",
        padding: "6px 12px",
        borderRadius: "6px",
        marginBottom: "16px",
        fontSize: "12px",
        color: "#94a3b8",
        display: "flex",
        justifyContent: "space-between"
      }}>
        <span>Focused App: <strong style={{ color: "#38bdf8", fontFamily: "monospace" }}>{deviceInfo.current_app || activePackageName || "Home Launcher"}</strong></span>
        <span>Display: <strong style={{ color: "#e2e8f0" }}>1080×2220</strong></span>
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
              onError={() => setScreenError(true)}
              onLoad={() => setScreenError(false)}
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

