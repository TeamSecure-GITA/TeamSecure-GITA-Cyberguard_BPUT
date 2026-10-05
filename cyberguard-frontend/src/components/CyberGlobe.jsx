import React, { useEffect, useRef, useState } from 'react';
import { Link2, Mail, UserCheck, Globe, Shield } from 'lucide-react';

// Continental anchor points [lat, lon] for digital cyber clusters
const CONTINENT_POINTS = [
  // North America
  [45, -100], [50, -115], [38, -95], [35, -85], [30, -98], [55, -120], [40, -74], [34, -118], [25, -80],
  // South America
  [-15, -55], [-5, -60], [-23, -46], [-34, -58], [5, -73], [-20, -65],
  // Europe
  [51, 0], [48, 2], [52, 13], [41, 12], [40, -3], [55, 37], [60, 25],
  // Africa
  [9, 20], [0, 25], [-26, 28], [30, 31], [6, 3], [-18, 47],
  // Asia
  [35, 105], [30, 114], [28, 77], [20, 78], [13, 80], [36, 138], [37, 127], [55, 83], [60, 100],
  // Australia
  [-25, 133], [-33, 151], [-37, 144], [-31, 115]
];

export default function CyberGlobe({ onOpenWorkspace, onSelectBadge }) {
  const canvasRef = useRef(null);
  const [activeBadge, setActiveBadge] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [rotation, setRotation] = useState({ x: 0.25, y: 0 });
  const lastMousePos = useRef({ x: 0, y: 0 });
  const animFrameRef = useRef(null);
  const rotationRef = useRef({ x: 0.25, y: 0 });

  useEffect(() => {
    rotationRef.current = rotation;
  }, [rotation]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.offsetWidth * window.devicePixelRatio || 520);
    let height = (canvas.height = canvas.offsetHeight * window.devicePixelRatio || 520);

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth * window.devicePixelRatio || 520;
      height = canvas.height = canvas.offsetHeight * window.devicePixelRatio || 520;
    };
    window.addEventListener('resize', handleResize);

    const radius = Math.min(width, height) * 0.35;
    const cx = width / 2;
    const cy = height / 2;

    // Pre-calculate latitude lines
    const latitudes = [-60, -40, -20, 0, 20, 40, 60];
    const longitudes = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330];

    let lastTime = performance.now();

    const render = (time) => {
      const dt = (time - lastTime) / 1000;
      lastTime = time;

      if (!isDragging) {
        rotationRef.current.y += dt * 0.45; // Smooth rotation
      }

      ctx.clearRect(0, 0, width, height);

      const rotY = rotationRef.current.y;
      const rotX = rotationRef.current.x;

      // Helper to project 3D sphere coordinate to 2D canvas
      const project = (latDeg, lonDeg) => {
        const phi = (latDeg * Math.PI) / 180;
        const theta = ((lonDeg * Math.PI) / 180) + rotY;

        let x = radius * Math.cos(phi) * Math.sin(theta);
        let y = -radius * Math.sin(phi);
        let z = radius * Math.cos(phi) * Math.cos(theta);

        // Apply tilt (rotX)
        const yRot = y * Math.cos(rotX) - z * Math.sin(rotX);
        const zRot = y * Math.sin(rotX) + z * Math.cos(rotX);

        // Perspective factor
        const fov = 800;
        const scale = fov / (fov - zRot);
        const px = cx + x * scale;
        const py = cy + yRot * scale;

        return { x: px, y: py, z: zRot, visible: zRot > -radius * 0.2 };
      };

      // 1. Draw Outer Atmospheric Glow
      const glowGrad = ctx.createRadialGradient(cx, cy, radius * 0.7, cx, cy, radius * 1.35);
      glowGrad.addColorStop(0, 'rgba(6, 182, 212, 0.0)');
      glowGrad.addColorStop(0.7, 'rgba(6, 182, 212, 0.12)');
      glowGrad.addColorStop(0.85, 'rgba(16, 185, 129, 0.22)');
      glowGrad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
      ctx.fillStyle = glowGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // 2. Draw Sphere Background Disc (Deep cosmic midnight)
      const sphereBg = ctx.createRadialGradient(cx - radius * 0.3, cy - radius * 0.3, 10, cx, cy, radius);
      sphereBg.addColorStop(0, '#0a2540');
      sphereBg.addColorStop(0.6, '#041628');
      sphereBg.addColorStop(1, '#020b18');
      ctx.fillStyle = sphereBg;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // 3. Draw Longitude Wireframes
      longitudes.forEach((lon) => {
        ctx.beginPath();
        let first = true;
        for (let lat = -85; lat <= 85; lat += 5) {
          const pt = project(lat, lon);
          if (first) {
            ctx.moveTo(pt.x, pt.y);
            first = false;
          } else {
            ctx.lineTo(pt.x, pt.y);
          }
        }
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.16)';
        ctx.lineWidth = 1 * window.devicePixelRatio;
        ctx.stroke();
      });

      // 4. Draw Latitude Wireframes
      latitudes.forEach((lat) => {
        ctx.beginPath();
        let first = true;
        for (let lon = 0; lon <= 360; lon += 8) {
          const pt = project(lat, lon);
          if (first) {
            ctx.moveTo(pt.x, pt.y);
            first = false;
          } else {
            ctx.lineTo(pt.x, pt.y);
          }
        }
        ctx.strokeStyle = lat === 0 ? 'rgba(52, 211, 153, 0.35)' : 'rgba(6, 182, 212, 0.14)';
        ctx.lineWidth = (lat === 0 ? 1.5 : 1) * window.devicePixelRatio;
        ctx.stroke();
      });

      // 5. Draw Digital Cyber Continent Points (Glowing clusters)
      CONTINENT_POINTS.forEach(([lat, lon]) => {
        // Main continental anchor
        const pt = project(lat, lon);
        if (pt.visible) {
          const alpha = Math.max(0.2, (pt.z + radius) / (2 * radius));
          
          // Outer halo
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 4 * window.devicePixelRatio, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(52, 211, 153, ${alpha * 0.4})`;
          ctx.fill();

          // Inner point
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 2 * window.devicePixelRatio, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(167, 243, 208, ${alpha})`;
          ctx.fill();

          // Scatter small secondary nodes
          [-2, 2].forEach((dLat) => {
            [-3, 3].forEach((dLon) => {
              const subPt = project(lat + dLat, lon + dLon);
              if (subPt.visible) {
                ctx.beginPath();
                ctx.arc(subPt.x, subPt.y, 1.2 * window.devicePixelRatio, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(56, 189, 248, ${alpha * 0.7})`;
                ctx.fill();
              }
            });
          });
        }
      });

      // 6. Draw Atmosphere Rim Ring
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.7)';
      ctx.lineWidth = 2 * window.devicePixelRatio;
      ctx.shadowColor = '#06b6d4';
      ctx.shadowBlur = 18 * window.devicePixelRatio;
      ctx.stroke();
      ctx.shadowBlur = 0; // Reset

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [isDragging]);

  // Mouse drag handlers for interactive exploration
  const handleMouseDown = (e) => {
    setIsDragging(true);
    lastMousePos.current = { x: e.clientX, y: e.clientY };
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    const dx = e.clientX - lastMousePos.current.x;
    const dy = e.clientY - lastMousePos.current.y;
    lastMousePos.current = { x: e.clientX, y: e.clientY };

    setRotation((prev) => ({
      x: Math.max(-0.6, Math.min(0.6, prev.x + dy * 0.005)),
      y: prev.y + dx * 0.008,
    }));
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const telemetryBadges = [
    {
      id: 'url',
      title: 'URL / WEB',
      desc: 'Malicious sites, phishing',
      icon: Link2,
      position: 'top-left', // Top-left of sphere
      className: 'top-2 sm:top-6 left-2 sm:left-4 border-cyan-500/40 text-cyan-400',
      lineClass: 'right-[-28px] bottom-[-16px] w-7 h-[1px] bg-cyan-400/50 rotate-[35deg]',
      dotColor: 'bg-cyan-400'
    },
    {
      id: 'ip',
      title: 'IP / SCAN',
      desc: 'Suspicious activity',
      icon: Mail,
      position: 'top-right', // Top-right of sphere
      className: 'top-4 sm:top-8 right-2 sm:right-4 border-emerald-500/40 text-emerald-400',
      lineClass: 'left-[-28px] bottom-[-16px] w-7 h-[1px] bg-emerald-400/50 -rotate-[35deg]',
      dotColor: 'bg-emerald-400'
    },
    {
      id: 'deepfake',
      title: 'DEEPFAKE / MEDIA',
      desc: 'Fake audio, image, video',
      icon: UserCheck,
      position: 'bottom-left', // Bottom-left of sphere
      className: 'bottom-16 sm:bottom-20 left-2 sm:left-4 border-indigo-400/40 text-indigo-400',
      lineClass: 'right-[-26px] top-[-12px] w-7 h-[1px] bg-indigo-400/50 -rotate-[30deg]',
      dotColor: 'bg-indigo-400'
    },
    {
      id: 'tor',
      title: 'TOR / RELAY',
      desc: 'Hide origin, evade tracking',
      icon: Globe,
      position: 'bottom-right', // Bottom-right of sphere
      className: 'bottom-16 sm:bottom-20 right-2 sm:right-4 border-amber-400/40 text-amber-400',
      lineClass: 'left-[-26px] top-[-12px] w-7 h-[1px] bg-amber-400/50 rotate-[30deg]',
      dotColor: 'bg-amber-400'
    },
  ];

  return (
    <div 
      className="relative w-full max-w-[560px] h-[440px] xs:h-[480px] sm:h-[540px] flex items-center justify-center select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      {/* 1. Underlying Radial Halo Background Glow */}
      <div 
        className="absolute inset-0 m-auto w-[320px] sm:w-[440px] h-[320px] sm:h-[440px] rounded-full pointer-events-none blur-[90px]"
        style={{
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.25) 0%, rgba(6, 182, 212, 0.22) 45%, rgba(2, 6, 23, 0) 75%)',
        }}
      />

      {/* 2. Interactive 3D Canvas Layer for the Rotating Cyber Globe */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing z-10"
        title="Interactive 3D Digital Globe - Drag to rotate"
      />

      {/* 3. Outer Concentric Cyber Rings (Overlaid CSS 3D Rings) */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center z-15">
        {/* Ring A: Outer Dashed Tech Circle */}
        <div 
          className="absolute w-[310px] h-[310px] sm:w-[410px] sm:h-[410px] rounded-full border border-cyan-500/25 border-dashed animate-[spin_100s_linear_infinite]"
        />

        {/* Ring B: Thin Cyan Radar Scope Circle */}
        <div 
          className="absolute w-[340px] h-[340px] sm:w-[450px] sm:h-[450px] rounded-full border border-cyan-400/15"
        />

        {/* Ring C: 3D Inclined Gyro Orbit 1 (Tilted Emerald) */}
        <div 
          className="absolute w-[290px] h-[145px] sm:w-[420px] sm:h-[210px] rounded-[50%] border-2 border-emerald-400/50"
          style={{
            transform: 'rotateX(72deg) rotateY(18deg) rotateZ(0deg)',
            boxShadow: '0 0 25px rgba(16, 185, 129, 0.25), inset 0 0 15px rgba(16, 185, 129, 0.15)',
            animation: 'gyro-spin-1 18s linear infinite',
          }}
        >
          <div className="absolute top-[-5px] left-1/2 -translate-x-1/2 w-2.5 h-2.5 rounded-full bg-emerald-300 shadow-[0_0_15px_#34d399,0_0_30px_#10b981]" />
        </div>

        {/* Ring D: 3D Inclined Gyro Orbit 2 (Tilted Cyan) */}
        <div 
          className="absolute w-[280px] h-[140px] sm:w-[400px] sm:h-[200px] rounded-[50%] border-2 border-cyan-400/50"
          style={{
            transform: 'rotateX(72deg) rotateY(-26deg) rotateZ(45deg)',
            boxShadow: '0 0 25px rgba(6, 182, 212, 0.25), inset 0 0 15px rgba(6, 182, 212, 0.15)',
            animation: 'gyro-spin-2 24s linear infinite',
          }}
        >
          <div className="absolute top-[-5px] left-1/2 -translate-x-1/2 w-2.5 h-2.5 rounded-full bg-cyan-300 shadow-[0_0_15px_#38bdf8,0_0_30px_#06b6d4]" />
        </div>
      </div>

      {/* 4. Central Glowing Holographic Shield Emblem with Monogram "C" */}
      <div 
        onClick={onOpenWorkspace}
        className="group relative z-25 w-24 h-24 sm:w-28 sm:h-28 rounded-2xl flex flex-col items-center justify-center cursor-pointer transition-transform duration-300 hover:scale-110 active:scale-95 shadow-[0_0_50px_rgba(16,185,129,0.55)]"
        title="Open CyberGuard Workspace"
      >
        {/* Shield Outer Aura */}
        <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-emerald-400/30 via-cyan-500/25 to-transparent blur-md group-hover:blur-lg transition-all" />

        {/* Shield Container Body */}
        <div 
          className="relative w-full h-full rounded-2xl flex flex-col items-center justify-center border-2 border-emerald-400/80 backdrop-blur-xl"
          style={{
            background: 'radial-gradient(circle at 40% 30%, rgba(6, 182, 212, 0.35) 0%, rgba(4, 20, 32, 0.95) 75%, rgba(2, 10, 19, 0.98) 100%)',
            boxShadow: 'inset 0 0 25px rgba(16, 185, 129, 0.4), 0 0 35px rgba(6, 182, 212, 0.35)',
          }}
        >
          {/* Subtle shield outline inside */}
          <Shield size={38} className="text-emerald-400/20 absolute" />

          {/* Monogram "C" Emblem */}
          <span 
            className="text-4xl sm:text-5xl font-black font-mono tracking-tighter text-emerald-300 drop-shadow-[0_0_18px_rgba(52,211,153,0.95)]"
          >
            C
          </span>

          <div className="absolute -bottom-2 flex items-center gap-1 px-2 py-0.5 rounded-full bg-[#051a28] border border-emerald-500/40 text-[9px] font-mono font-semibold text-emerald-300 tracking-wider shadow-md">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>SOC AI</span>
          </div>
        </div>
      </div>

      {/* 5. Hologram Pedestal / Platform at Base */}
      <div className="absolute bottom-2 sm:bottom-4 inset-x-0 mx-auto w-[240px] sm:w-[320px] flex flex-col items-center pointer-events-none z-10">
        {/* Upward Energy Cone Beam */}
        <div 
          className="w-[180px] sm:w-[240px] h-[60px] blur-sm opacity-60"
          style={{
            background: 'linear-gradient(to top, rgba(6, 182, 212, 0.35) 0%, rgba(16, 185, 129, 0.15) 50%, transparent 100%)',
            clipPath: 'polygon(15% 100%, 85% 100%, 100% 0%, 0% 0%)',
          }}
        />

        {/* Concentric Base Ellipses */}
        <div className="relative w-full h-[36px] flex items-center justify-center">
          <div className="absolute w-[220px] sm:w-[290px] h-[28px] rounded-[50%] border border-cyan-500/35 shadow-[0_0_15px_rgba(6,182,212,0.3)]" />
          <div className="absolute w-[160px] sm:w-[210px] h-[18px] rounded-[50%] border-2 border-emerald-400/50 shadow-[0_0_20px_rgba(16,185,129,0.4)]" />
          <div className="w-[80px] sm:w-[110px] h-[10px] rounded-[50%] bg-cyan-400/70 blur-[2px] shadow-[0_0_25px_#38bdf8]" />
        </div>
      </div>

      {/* 6. Floating Glassmorphic Telemetry Cards (Positioned exactly per reference image) */}
      {telemetryBadges.map((badge) => {
        const IconComponent = badge.icon;
        const isHovered = activeBadge === badge.id;

        return (
          <div
            key={badge.id}
            onMouseEnter={() => setActiveBadge(badge.id)}
            onMouseLeave={() => setActiveBadge(null)}
            onClick={() => onSelectBadge?.(badge.id)}
            className={`absolute z-30 flex items-center gap-2.5 px-3 py-2 rounded-xl backdrop-blur-md bg-[#041220]/85 border shadow-lg transition-all duration-300 cursor-pointer hover:scale-105 active:scale-95 ${badge.className} ${
              isHovered ? 'shadow-[0_0_25px_rgba(6,182,212,0.5)] border-cyan-400' : ''
            }`}
          >
            {/* Icon Pill */}
            <div className="p-1.5 rounded-lg bg-slate-900/80 border border-slate-700/80 shrink-0">
              <IconComponent size={14} className={badge.dotColor.replace('bg-', 'text-')} />
            </div>

            {/* Texts */}
            <div className="flex flex-col text-left">
              <div className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${badge.dotColor} animate-pulse`} />
                <span className="font-mono text-xs font-bold text-white tracking-wide">
                  {badge.title}
                </span>
              </div>
              <span className="text-[10px] text-slate-300 font-normal leading-tight mt-0.5">
                {badge.desc}
              </span>
            </div>

            {/* Connecting decorative anchor line (on desktop) */}
            <div className={`hidden sm:block absolute ${badge.lineClass}`} />
          </div>
        );
      })}
    </div>
  );
}
