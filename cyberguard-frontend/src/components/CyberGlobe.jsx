import React, { useEffect, useRef, useState } from 'react';
import { Link2, Mail, User, Shield, Share2 } from 'lucide-react';

// Continental anchor points [lat, lon] for digital cyber clusters
const CONTINENT_POINTS = [
  // North America
  [49, -123], [45, -100], [50, -115], [38, -95], [35, -85], [30, -98], [55, -120], 
  [40, -74], [34, -118], [25, -80], [60, -135], [32, -106], [42, -71], [47, -122],
  // South America
  [-15, -55], [-5, -60], [-23, -46], [-34, -58], [5, -73], [-20, -65], [-12, -77], [-30, -51],
  // Europe
  [51, 0], [48, 2], [52, 13], [41, 12], [40, -3], [55, 37], [60, 25], [59, 18], [45, 9], [53, -6],
  // Africa
  [9, 20], [0, 25], [-26, 28], [30, 31], [6, 3], [-18, 47], [15, 32], [-33, 18], [36, 3],
  // Asia & Middle East
  [35, 105], [30, 114], [28, 77], [20, 78], [13, 80], [36, 138], [37, 127], [55, 83], 
  [60, 100], [25, 55], [31, 35], [1, 103], [14, 100], [22, 114], [39, 116], [31, 121],
  // Australia & Oceania
  [-25, 133], [-33, 151], [-37, 144], [-31, 115], [-42, 147], [-36, 174]
];

// Active cyber threat connection arcs [from [lat, lon], to [lat, lon]]
const THREAT_ARCS = [
  { from: [40, -74], to: [51, 0], color: 'rgba(6, 182, 212, 0.65)' },    // NY to London
  { from: [51, 0], to: [35, 138], color: 'rgba(16, 185, 129, 0.65)' },    // London to Tokyo
  { from: [37, 127], to: [34, -118], color: 'rgba(6, 182, 212, 0.6)' },  // Seoul to LA
  { from: [28, 77], to: [52, 13], color: 'rgba(56, 189, 248, 0.6)' },     // Delhi to Berlin
  { from: [-33, 151], to: [1, 103], color: 'rgba(16, 185, 129, 0.6)' },   // Sydney to Singapore
];

export default function CyberGlobe({ onOpenWorkspace, onSelectBadge }) {
  const canvasRef = useRef(null);
  const [activeBadge, setActiveBadge] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [rotation, setRotation] = useState({ x: 0.22, y: 0.4 });
  const lastMousePos = useRef({ x: 0, y: 0 });
  const animFrameRef = useRef(null);
  const rotationRef = useRef({ x: 0.22, y: 0.4 });

  useEffect(() => {
    rotationRef.current = rotation;
  }, [rotation]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let width = (canvas.width = canvas.offsetWidth * (window.devicePixelRatio || 2));
    let height = (canvas.height = canvas.offsetHeight * (window.devicePixelRatio || 2));

    const handleResize = () => {
      if (!canvas) return;
      width = canvas.width = canvas.offsetWidth * (window.devicePixelRatio || 2);
      height = canvas.height = canvas.offsetHeight * (window.devicePixelRatio || 2);
    };
    window.addEventListener('resize', handleResize);

    const radius = Math.min(width, height) * 0.36;
    const cx = width / 2;
    const cy = height / 2;

    const latitudes = [-60, -40, -20, 0, 20, 40, 60];
    const longitudes = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330];

    let lastTime = performance.now();

    const render = (time) => {
      const dt = (time - lastTime) / 1000;
      lastTime = time;

      if (!isDragging) {
        rotationRef.current.y += dt * 0.38; // Constant smooth rotation
      }

      ctx.clearRect(0, 0, width, height);

      const rotY = rotationRef.current.y;
      const rotX = rotationRef.current.x;

      // 3D coordinate projection
      const project = (latDeg, lonDeg, alt = 1.0) => {
        const phi = (latDeg * Math.PI) / 180;
        const theta = ((lonDeg * Math.PI) / 180) + rotY;

        const r = radius * alt;
        let x = r * Math.cos(phi) * Math.sin(theta);
        let y = -r * Math.sin(phi);
        let z = r * Math.cos(phi) * Math.cos(theta);

        // Apply tilt
        const yRot = y * Math.cos(rotX) - z * Math.sin(rotX);
        const zRot = y * Math.sin(rotX) + z * Math.cos(rotX);

        const fov = 900;
        const scale = fov / (fov - zRot);
        const px = cx + x * scale;
        const py = cy + yRot * scale;

        return { x: px, y: py, z: zRot, visible: zRot > -radius * 0.25, scale };
      };

      // 1. Deep Atmospheric Outer Halo
      const outerGlow = ctx.createRadialGradient(cx, cy, radius * 0.75, cx, cy, radius * 1.38);
      outerGlow.addColorStop(0, 'rgba(6, 182, 212, 0)');
      outerGlow.addColorStop(0.65, 'rgba(6, 182, 212, 0.08)');
      outerGlow.addColorStop(0.85, 'rgba(16, 185, 129, 0.2)');
      outerGlow.addColorStop(1, 'rgba(6, 182, 212, 0)');
      ctx.fillStyle = outerGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.38, 0, Math.PI * 2);
      ctx.fill();

      // 2. Translucent Planetary Core Sphere
      const sphereGradient = ctx.createRadialGradient(
        cx - radius * 0.25,
        cy - radius * 0.25,
        radius * 0.1,
        cx,
        cy,
        radius
      );
      sphereGradient.addColorStop(0, 'rgba(7, 30, 58, 0.95)');
      sphereGradient.addColorStop(0.55, 'rgba(3, 18, 38, 0.95)');
      sphereGradient.addColorStop(0.9, 'rgba(1, 10, 22, 0.98)');
      sphereGradient.addColorStop(1, 'rgba(6, 182, 212, 0.3)');
      ctx.fillStyle = sphereGradient;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.fill();

      // 3. Longitude Grid Lines
      longitudes.forEach((lon) => {
        ctx.beginPath();
        let started = false;
        for (let lat = -85; lat <= 85; lat += 4) {
          const pt = project(lat, lon);
          if (pt.visible) {
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.18)';
        ctx.lineWidth = 1 * (window.devicePixelRatio || 2);
        ctx.stroke();
      });

      // 4. Latitude Grid Lines
      latitudes.forEach((lat) => {
        ctx.beginPath();
        let started = false;
        for (let lon = 0; lon <= 360; lon += 6) {
          const pt = project(lat, lon);
          if (pt.visible) {
            if (!started) {
              ctx.moveTo(pt.x, pt.y);
              started = true;
            } else {
              ctx.lineTo(pt.x, pt.y);
            }
          } else {
            started = false;
          }
        }
        ctx.strokeStyle = lat === 0 ? 'rgba(52, 211, 153, 0.45)' : 'rgba(6, 182, 212, 0.16)';
        ctx.lineWidth = (lat === 0 ? 1.6 : 1) * (window.devicePixelRatio || 2);
        ctx.stroke();
      });

      // 5. Continental Cyber Clusters
      CONTINENT_POINTS.forEach(([lat, lon]) => {
        const pt = project(lat, lon);
        if (pt.visible) {
          const alpha = Math.min(1, Math.max(0.15, (pt.z + radius) / (2 * radius)));

          // Primary Node Halo
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 4.5 * (window.devicePixelRatio || 2), 0, Math.PI * 2);
          ctx.fillStyle = `rgba(52, 211, 153, ${alpha * 0.45})`;
          ctx.fill();

          // Bright Core Point
          ctx.beginPath();
          ctx.arc(pt.x, pt.y, 2.2 * (window.devicePixelRatio || 2), 0, Math.PI * 2);
          ctx.fillStyle = `rgba(167, 243, 208, ${alpha * 0.95})`;
          ctx.fill();

          // Denser secondary micro-nodes around continents
          const offsets = [
            [-2.5, -2], [2.5, 2], [-1.5, 3.5], [3, -2.5], [-3.5, 1.5]
          ];
          offsets.forEach(([dLat, dLon]) => {
            const subPt = project(lat + dLat, lon + dLon);
            if (subPt.visible) {
              ctx.beginPath();
              ctx.arc(subPt.x, subPt.y, 1.2 * (window.devicePixelRatio || 2), 0, Math.PI * 2);
              ctx.fillStyle = `rgba(56, 189, 248, ${alpha * 0.75})`;
              ctx.fill();
            }
          });
        }
      });

      // 6. Threat Connection Arcs
      THREAT_ARCS.forEach((arc) => {
        const p1 = project(arc.from[0], arc.from[1]);
        const p2 = project(arc.to[0], arc.to[1]);

        if (p1.visible || p2.visible) {
          // Calculate midpoint elevated above globe surface
          const midLat = (arc.from[0] + arc.to[0]) / 2;
          const midLon = (arc.from[1] + arc.to[1]) / 2;
          const midPt = project(midLat, midLon, 1.22); // Arc elevation

          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.quadraticCurveTo(midPt.x, midPt.y, p2.x, p2.y);
          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 1.3 * (window.devicePixelRatio || 2);
          ctx.stroke();

          // Pulsing pulse packet along arc
          const t = (time * 0.001) % 1;
          const pulseX = (1 - t) * (1 - t) * p1.x + 2 * (1 - t) * t * midPt.x + t * t * p2.x;
          const pulseY = (1 - t) * (1 - t) * p1.y + 2 * (1 - t) * t * midPt.y + t * t * p2.y;

          ctx.beginPath();
          ctx.arc(pulseX, pulseY, 2.5 * (window.devicePixelRatio || 2), 0, Math.PI * 2);
          ctx.fillStyle = '#ffffff';
          ctx.shadowColor = '#00f5ff';
          ctx.shadowBlur = 10 * (window.devicePixelRatio || 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // 7. Vibrant Glowing Atmosphere Rim
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.85)';
      ctx.lineWidth = 2.2 * (window.devicePixelRatio || 2);
      ctx.shadowColor = '#06b6d4';
      ctx.shadowBlur = 24 * (window.devicePixelRatio || 2);
      ctx.stroke();
      ctx.shadowBlur = 0;

      animFrameRef.current = requestAnimationFrame(render);
    };

    animFrameRef.current = requestAnimationFrame(render);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [isDragging]);

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

  // Exactly matching the 4 HUD badges in the reference image
  const telemetryBadges = [
    {
      id: 'url',
      title: 'URL / WEB',
      desc: 'Malicious sites, phishing',
      icon: Link2,
      cardPosition: 'top-2 sm:top-5 left-1 sm:left-4',
      accentColor: '#06b6d4',
      borderClass: 'border-cyan-500/40 text-cyan-400',
      iconBg: 'bg-cyan-950/70 border-cyan-500/40 text-cyan-400',
      pointerSvg: (
        <svg className="hidden sm:block absolute -right-10 -bottom-6 w-12 h-8 pointer-events-none overflow-visible">
          <polyline points="0,0 24,18 42,24" fill="none" stroke="#06b6d4" strokeWidth="1.5" strokeOpacity="0.75" />
          <circle cx="42" cy="24" r="3" fill="#22d3ee" className="animate-pulse" />
        </svg>
      ),
    },
    {
      id: 'ip',
      title: 'IP / SCAN',
      desc: 'Suspicious activity',
      icon: Mail,
      cardPosition: 'top-3 sm:top-6 right-1 sm:right-4',
      accentColor: '#38bdf8',
      borderClass: 'border-cyan-500/40 text-cyan-400',
      iconBg: 'bg-cyan-950/70 border-cyan-500/40 text-cyan-400',
      pointerSvg: (
        <svg className="hidden sm:block absolute -left-10 -bottom-6 w-12 h-8 pointer-events-none overflow-visible">
          <polyline points="48,0 24,18 6,24" fill="none" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.75" />
          <circle cx="6" cy="24" r="3" fill="#38bdf8" className="animate-pulse" />
        </svg>
      ),
    },
    {
      id: 'deepfake',
      title: 'DEEPFAKE / MEDIA',
      desc: 'Fake audio, image, video',
      icon: User,
      cardPosition: 'bottom-16 sm:bottom-20 left-1 sm:left-4',
      accentColor: '#22d3ee',
      borderClass: 'border-cyan-500/40 text-cyan-400',
      iconBg: 'bg-cyan-950/70 border-cyan-500/40 text-cyan-400',
      pointerSvg: (
        <svg className="hidden sm:block absolute -right-10 -top-6 w-12 h-8 pointer-events-none overflow-visible">
          <polyline points="0,28 24,10 42,4" fill="none" stroke="#22d3ee" strokeWidth="1.5" strokeOpacity="0.75" />
          <circle cx="42" cy="4" r="3" fill="#22d3ee" className="animate-pulse" />
        </svg>
      ),
    },
    {
      id: 'tor',
      title: 'TOR / RELAY',
      desc: 'Hide origin, evade tracking',
      icon: Share2,
      cardPosition: 'bottom-16 sm:bottom-20 right-1 sm:right-4',
      accentColor: '#f59e0b',
      borderClass: 'border-amber-500/40 text-amber-400',
      iconBg: 'bg-amber-950/60 border-amber-500/40 text-amber-400',
      pointerSvg: (
        <svg className="hidden sm:block absolute -left-10 -top-6 w-12 h-8 pointer-events-none overflow-visible">
          <polyline points="48,28 24,10 6,4" fill="none" stroke="#f59e0b" strokeWidth="1.5" strokeOpacity="0.75" />
          <circle cx="6" cy="4" r="3" fill="#f59e0b" className="animate-pulse" />
        </svg>
      ),
    },
  ];

  return (
    <div
      className="relative w-full max-w-[580px] h-[460px] xs:h-[500px] sm:h-[560px] flex items-center justify-center select-none"
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
    >
      {/* 1. Underlying Radial Halo Background Glow */}
      <div
        className="absolute inset-0 m-auto w-[340px] sm:w-[460px] h-[340px] sm:h-[460px] rounded-full pointer-events-none blur-[95px]"
        style={{
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.28) 0%, rgba(6, 182, 212, 0.25) 45%, rgba(2, 6, 23, 0) 75%)',
        }}
      />

      {/* 2. Interactive 3D Canvas Layer for the Rotating Cyber Globe */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 w-full h-full cursor-grab active:cursor-grabbing z-10"
        title="Interactive 3D Digital Globe - Drag to rotate"
      />

      {/* 3. Outer Concentric Cyber Rings (3D Orbital Rings) */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center z-15">
        {/* Ring A: Outer Circular Radar Ring */}
        <div className="absolute w-[330px] h-[330px] sm:w-[440px] sm:h-[440px] rounded-full border border-cyan-500/25 border-dashed animate-[spin_120s_linear_infinite]" />

        {/* Ring B: Secondary Atmospheric Ring */}
        <div className="absolute w-[360px] h-[360px] sm:w-[475px] sm:h-[475px] rounded-full border border-cyan-400/15" />

        {/* Ring C: 3D Inclined Gyroscopic Orbit 1 (Tilted Emerald) */}
        <div
          className="absolute w-[310px] h-[155px] sm:w-[450px] sm:h-[225px] rounded-[50%] border-2 border-emerald-400/50"
          style={{
            transform: 'rotateX(72deg) rotateY(18deg) rotateZ(0deg)',
            boxShadow: '0 0 25px rgba(16, 185, 129, 0.3), inset 0 0 15px rgba(16, 185, 129, 0.15)',
          }}
        >
          {/* Orbital Satellite Photon */}
          <div className="absolute top-[-6px] left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-emerald-300 shadow-[0_0_15px_#34d399,0_0_30px_#10b981] animate-pulse" />
        </div>

        {/* Ring D: 3D Inclined Gyroscopic Orbit 2 (Tilted Cyan) */}
        <div
          className="absolute w-[300px] h-[150px] sm:w-[430px] sm:h-[215px] rounded-[50%] border-2 border-cyan-400/50"
          style={{
            transform: 'rotateX(72deg) rotateY(-26deg) rotateZ(45deg)',
            boxShadow: '0 0 25px rgba(6, 182, 212, 0.3), inset 0 0 15px rgba(6, 182, 212, 0.15)',
          }}
        >
          {/* Orbital Satellite Photon */}
          <div className="absolute top-[-6px] left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-cyan-300 shadow-[0_0_15px_#38bdf8,0_0_30px_#06b6d4] animate-pulse" />
        </div>
      </div>

      {/* 4. Central Holographic Cyber Shield with "C" Emblem (Exact Replica from Screenshot) */}
      <div
        onClick={onOpenWorkspace}
        className="group relative z-25 w-24 h-28 sm:w-28 sm:h-32 flex items-center justify-center cursor-pointer transition-transform duration-300 hover:scale-110 active:scale-95 drop-shadow-[0_0_40px_rgba(6,182,212,0.7)]"
        title="Open CyberGuard Workspace"
      >
        <svg
          viewBox="0 0 100 120"
          className="w-full h-full overflow-visible"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {/* Outer neon border gradient */}
            <linearGradient id="shieldBorder" x1="50" y1="0" x2="50" y2="120" gradientUnits="userSpaceOnUse">
              <stop stopColor="#00f5ff" />
              <stop offset="0.5" stopColor="#00e699" />
              <stop offset="1" stopColor="#06b6d4" />
            </linearGradient>

            {/* Inner background gradient */}
            <radialGradient id="shieldBg" cx="50%" cy="40%" r="60%">
              <stop offset="0%" stopColor="#042c3d" stopOpacity="0.95" />
              <stop offset="70%" stopColor="#021424" stopOpacity="0.98" />
              <stop offset="100%" stopColor="#010c17" stopOpacity="1" />
            </radialGradient>

            {/* Inner neon border gradient */}
            <linearGradient id="innerShieldBorder" x1="50" y1="10" x2="50" y2="110" gradientUnits="userSpaceOnUse">
              <stop stopColor="#00f5ff" stopOpacity="0.6" />
              <stop offset="1" stopColor="#00e699" stopOpacity="0.3" />
            </linearGradient>

            {/* Intense cyan glow filter */}
            <filter id="neonGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Outer Shield Shell */}
          <path
            d="M 50,6 C 64,6 84,11 93,20 C 93,56 82,92 50,116 C 18,92 7,56 7,20 C 16,11 36,6 50,6 Z"
            fill="url(#shieldBg)"
            stroke="url(#shieldBorder)"
            strokeWidth="3.2"
            strokeLinejoin="round"
            filter="url(#neonGlow)"
          />

          {/* Inner Accent Line */}
          <path
            d="M 50,14 C 61,14 77,18 84,25 C 84,54 75,84 50,105 C 25,84 16,54 16,25 C 23,18 39,14 50,14 Z"
            fill="none"
            stroke="url(#innerShieldBorder)"
            strokeWidth="1.4"
            strokeLinejoin="round"
            strokeDasharray="4 2"
          />

          {/* Glowing Centered "C" Emblem */}
          <text
            x="50"
            y="72"
            textAnchor="middle"
            fill="#00e699"
            fontSize="44"
            fontWeight="900"
            fontFamily="Space Grotesk, system-ui, sans-serif"
            letterSpacing="-1.5"
            style={{
              filter: 'drop-shadow(0 0 16px rgba(0, 230, 153, 0.95)) drop-shadow(0 0 4px #00f5ff)',
            }}
          >
            C
          </text>
        </svg>

        {/* Floating Mini Status Chip */}
        <div className="absolute -bottom-3 flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-[#031525]/90 border border-emerald-400/50 text-[10px] font-mono font-bold text-emerald-300 shadow-[0_0_15px_rgba(16,185,129,0.4)]">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>CYBERGUARD</span>
        </div>
      </div>

      {/* 5. Hologram Pedestal / Platform at Base (Matching Reference Image) */}
      <div className="absolute bottom-1 sm:bottom-3 inset-x-0 mx-auto w-[260px] sm:w-[340px] flex flex-col items-center pointer-events-none z-10">
        {/* Upward Energy Cone Beam */}
        <div
          className="w-[200px] sm:w-[260px] h-[55px] blur-sm opacity-60"
          style={{
            background: 'linear-gradient(to top, rgba(6, 182, 212, 0.4) 0%, rgba(16, 185, 129, 0.15) 50%, transparent 100%)',
            clipPath: 'polygon(15% 100%, 85% 100%, 100% 0%, 0% 0%)',
          }}
        />

        {/* Concentric Base Ellipses */}
        <div className="relative w-full h-[32px] flex items-center justify-center">
          <div className="absolute w-[240px] sm:w-[310px] h-[26px] rounded-[50%] border border-cyan-500/40 shadow-[0_0_20px_rgba(6,182,212,0.35)]" />
          <div className="absolute w-[180px] sm:w-[230px] h-[18px] rounded-[50%] border-2 border-emerald-400/60 shadow-[0_0_25px_rgba(16,185,129,0.5)]" />
          <div className="w-[90px] sm:w-[130px] h-[10px] rounded-[50%] bg-cyan-400/80 blur-[2px] shadow-[0_0_30px_#38bdf8]" />
        </div>
      </div>

      {/* 6. Floating Glassmorphic Telemetry Cards (4 Exact Columns from Reference) */}
      {telemetryBadges.map((badge) => {
        const IconComponent = badge.icon;
        const isHovered = activeBadge === badge.id;

        return (
          <div
            key={badge.id}
            onMouseEnter={() => setActiveBadge(badge.id)}
            onMouseLeave={() => setActiveBadge(null)}
            onClick={() => onSelectBadge?.(badge.id)}
            className={`absolute z-30 flex items-center gap-3 px-3.5 py-2.5 rounded-xl backdrop-blur-md bg-[#041220]/90 border shadow-xl transition-all duration-300 cursor-pointer hover:scale-105 active:scale-95 ${badge.cardPosition} ${badge.borderClass} ${
              isHovered ? 'shadow-[0_0_30px_rgba(6,182,212,0.6)] border-cyan-300' : 'shadow-[0_4px_20px_rgba(0,0,0,0.6)]'
            }`}
          >
            {/* Left Square Icon Pill */}
            <div className={`p-2 rounded-lg border flex items-center justify-center shrink-0 ${badge.iconBg}`}>
              <IconComponent size={15} style={{ color: badge.accentColor }} />
            </div>

            {/* Texts */}
            <div className="flex flex-col text-left">
              <span className="font-mono text-xs font-bold text-white tracking-wide">
                {badge.title}
              </span>
              <span className="text-[11px] text-slate-300 font-normal leading-tight mt-0.5">
                {badge.desc}
              </span>
            </div>

            {/* Cyber Pointer Line */}
            {badge.pointerSvg}
          </div>
        );
      })}
    </div>
  );
}
