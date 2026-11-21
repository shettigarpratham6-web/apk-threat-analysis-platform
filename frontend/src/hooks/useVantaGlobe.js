import { useEffect, useRef } from "react";

/**
 * Mounts the same Vanta globe used on the landing page.
 * Attach the returned ref to a fixed, full-screen <div className="landing-background" />.
 * (Vanta + THREE are loaded as <script> tags in index.html.)
 */
export default function useVantaGlobe() {
  const bgRef = useRef(null);

  useEffect(() => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion || !window.VANTA || !window.THREE || !bgRef.current) return;
    const effect = window.VANTA.GLOBE({
      el: bgRef.current,
      THREE: window.THREE,
      mouseControls: true,
      touchControls: true,
      gyroControls: false,
      minHeight: 200.0,
      minWidth: 200.0,
      scale: 1.0,
      scaleMobile: 1.0,
      color: 0x10b981,
      color2: 0x047857,
      backgroundColor: 0x050811,
    });
    return () => effect.destroy();
  }, []);

  return bgRef;
}
