import React, { useState, useEffect, useRef } from 'react';
import { Play, Pause, Volume2, VolumeX, Maximize2, X, Sparkles, Shield, ChevronUp } from 'lucide-react';

const TOTAL_DURATION_SECONDS = 103; // 1:43 total duration matching reference screenshot

const BRIEFING_SEGMENTS = [
  { start: 0, end: 24, title: 'Autonomous Signal Ingestion', desc: 'Real-time telemetry streaming from campus DNS, LDAP & edge gateways' },
  { start: 25, end: 54, title: 'Multi-Engine Phishing Triangulation', desc: 'Analyzing punycode, DOM payloads, and zero-day certificate age' },
  { start: 55, end: 82, title: 'Acoustic Voice Clone Forensics', desc: 'Spectral frequency inspection for synthetic diffusion artifacts' },
  { start: 83, end: 103, title: 'Instant WAF Mitigation & Incident Containment', desc: 'Dispatching dynamic Cloudflare edge blocks and credential resets' },
];

export default function CyberVideoPlayerBar({ 
  isOpen = true, 
  onClose, 
  onOpenFullDemo,
  themeMode = 'dark' 
}) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [playbackSpeed, setPlaybackSpeed] = useState(1.0);
  const [isMuted, setIsMuted] = useState(false);
  const [isMinimized, setIsMinimized] = useState(!isOpen);
  const [showTooltip, setShowTooltip] = useState(false);
  const timerRef = useRef(null);

  const isLight = themeMode === 'judge-white' || themeMode === 'light';

  useEffect(() => {
    setIsMinimized(!isOpen);
  }, [isOpen]);

  useEffect(() => {
    if (isPlaying) {
      timerRef.current = setInterval(() => {
        setCurrentTime((prev) => {
          if (prev >= TOTAL_DURATION_SECONDS) {
            setIsPlaying(false);
            return 0;
          }
          return prev + 1;
        });
      }, 1000 / playbackSpeed);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [isPlaying, playbackSpeed]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  const currentSegment = BRIEFING_SEGMENTS.find(
    (s) => currentTime >= s.start && currentTime <= s.end
  ) || BRIEFING_SEGMENTS[0];

  const handleScrubberClick = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const percentage = Math.max(0, Math.min(1, clickX / rect.width));
    setCurrentTime(Math.round(percentage * TOTAL_DURATION_SECONDS));
  };

  const cycleSpeed = () => {
    const speeds = [1.0, 1.25, 1.5, 2.0];
    const nextIdx = (speeds.indexOf(playbackSpeed) + 1) % speeds.length;
    setPlaybackSpeed(speeds[nextIdx]);
  };

  if (isMinimized) {
    return (
      <button
        onClick={() => {
          setIsMinimized(false);
          setIsPlaying(true);
        }}
        className={`fixed bottom-4 left-1/2 -translate-x-1/2 z-40 flex items-center gap-2.5 px-4 py-2 rounded-full shadow-2xl backdrop-blur-md transition-all duration-300 hover:scale-105 cursor-pointer ${
          isLight
            ? 'bg-white/95 text-slate-800 border border-slate-300/80 shadow-slate-300/60 hover:border-cyan-500'
            : 'bg-[#061424]/95 text-cyan-300 border border-cyan-500/40 shadow-[0_0_25px_rgba(6,182,212,0.3)] hover:border-cyan-400'
        }`}
        title="Resume Video Briefing"
      >
        <div className="w-5 h-5 rounded-full bg-cyan-500/20 flex items-center justify-center">
          <Play size={10} className="fill-cyan-400 text-cyan-400" />
        </div>
        <span className="text-xs font-mono font-bold tracking-wide">
          WATCH DEMO BRIEFING ({formatTime(currentTime)} / 1:43)
        </span>
        <ChevronUp size={14} className="opacity-70" />
      </button>
    );
  }

  const progressPercent = (currentTime / TOTAL_DURATION_SECONDS) * 100;

  return (
    <div className="fixed bottom-4 inset-x-0 mx-auto w-[94%] max-w-3xl z-40 px-2 pointer-events-auto transition-all duration-300 animate-in fade-in slide-in-from-bottom-3">
      {/* Active Briefing Capsule */}
      {isPlaying && (
        <div className={`mb-2 mx-auto max-w-md px-3.5 py-1.5 rounded-full text-center text-xs backdrop-blur-md transition-all shadow-lg flex items-center justify-between gap-2 border ${
          isLight
            ? 'bg-white/95 border-emerald-500/30 text-slate-800 shadow-slate-200/80'
            : 'bg-[#031120]/95 border-cyan-500/30 text-slate-200 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
        }`}>
          <div className="flex items-center gap-2 overflow-hidden text-left">
            <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-ping" />
            <span className="font-mono text-[11px] font-bold text-emerald-500 uppercase shrink-0">
              {currentSegment.title}:
            </span>
            <span className="text-[11px] text-slate-600 dark:text-slate-300 truncate">
              {currentSegment.desc}
            </span>
          </div>
          <button 
            onClick={onOpenFullDemo}
            className="text-[10px] font-mono text-cyan-500 dark:text-cyan-400 font-bold hover:underline shrink-0"
          >
            Interactive →
          </button>
        </div>
      )}

      {/* Main Video Controls Bar matching exact reference layout */}
      <div 
        className={`w-full px-4 sm:px-6 py-2.5 sm:py-3 rounded-2xl sm:rounded-full border backdrop-blur-xl shadow-2xl flex items-center justify-between gap-3 sm:gap-4 transition-all ${
          isLight
            ? 'bg-white/95 border-slate-300/80 text-slate-800 shadow-slate-300/70'
            : 'bg-[#031020]/90 border-cyan-500/30 text-white shadow-[0_10px_40px_rgba(0,0,0,0.8),0_0_25px_rgba(6,182,212,0.2)]'
        }`}
      >
        {/* Play / Pause Toggle Button */}
        <button
          type="button"
          onClick={() => setIsPlaying(!isPlaying)}
          className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 transition-transform hover:scale-110 active:scale-95 cursor-pointer ${
            isLight
              ? 'bg-slate-900 text-white hover:bg-slate-800'
              : 'bg-white/90 text-slate-950 hover:bg-cyan-300 hover:text-slate-950'
          }`}
          title={isPlaying ? 'Pause Demo' : 'Play Demo'}
          aria-label={isPlaying ? 'Pause Demo' : 'Play Demo'}
        >
          {isPlaying ? (
            <Pause size={13} className="fill-current" />
          ) : (
            <Play size={13} className="fill-current ml-0.5" />
          )}
        </button>

        {/* Current Time Indicator */}
        <span className="font-mono text-xs sm:text-sm font-semibold shrink-0 text-slate-400 dark:text-slate-300">
          {formatTime(currentTime)}
        </span>

        {/* Scrubber Progress Bar */}
        <div 
          onClick={handleScrubberClick}
          onMouseEnter={() => setShowTooltip(true)}
          onMouseLeave={() => setShowTooltip(false)}
          className="relative flex-1 h-2 rounded-full bg-slate-300/50 dark:bg-slate-700/60 cursor-pointer overflow-visible group"
        >
          {/* Filled Progress Track */}
          <div 
            className="absolute top-0 left-0 h-full rounded-full transition-all duration-100"
            style={{
              width: `${progressPercent}%`,
              background: isLight 
                ? 'linear-gradient(90deg, #0284c7 0%, #059669 100%)' 
                : 'linear-gradient(90deg, #00e699 0%, #06b6d4 100%)',
              boxShadow: isLight ? 'none' : '0 0 10px rgba(6, 182, 212, 0.7)'
            }}
          />

          {/* Scrubber Thumb Knob */}
          <div 
            className={`absolute top-1/2 -translate-y-1/2 w-3.5 h-3.5 rounded-full transition-all group-hover:scale-125 ${
              isLight ? 'bg-slate-900 border-2 border-white' : 'bg-cyan-300 border border-white shadow-[0_0_10px_#22d3ee]'
            }`}
            style={{ left: `calc(${progressPercent}% - 7px)` }}
          />
        </div>

        {/* Total Duration: 1:43 */}
        <span className="font-mono text-xs sm:text-sm font-semibold shrink-0 text-slate-400 dark:text-slate-400">
          1:43
        </span>

        {/* Speed Multiplier Pill: 1.0x */}
        <button
          type="button"
          onClick={cycleSpeed}
          className={`px-2 py-0.5 rounded text-xs font-mono font-bold transition-colors cursor-pointer shrink-0 ${
            isLight
              ? 'bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300'
              : 'bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-slate-700'
          }`}
          title="Playback Speed"
        >
          {playbackSpeed.toFixed(1)}x
        </button>

        {/* Volume / Mute Button */}
        <button
          type="button"
          onClick={() => setIsMuted(!isMuted)}
          className="text-slate-400 hover:text-cyan-400 transition-colors p-1 cursor-pointer shrink-0"
          title={isMuted ? 'Unmute Audio' : 'Mute Audio'}
        >
          {isMuted ? <VolumeX size={17} /> : <Volume2 size={17} />}
        </button>

        {/* Interactive Fullscreen / Simulator Launch Button */}
        <button
          type="button"
          onClick={onOpenFullDemo}
          className="text-slate-400 hover:text-emerald-400 transition-colors p-1 cursor-pointer shrink-0"
          title="Open Fullscreen Interactive Simulator"
        >
          <Maximize2 size={16} />
        </button>

        {/* Dismiss / Close Button */}
        <button
          type="button"
          onClick={() => {
            setIsPlaying(false);
            if (onClose) onClose();
            else setIsMinimized(true);
          }}
          className="text-slate-400 hover:text-rose-400 transition-colors p-1 cursor-pointer shrink-0 ml-0.5"
          title="Close Video Bar"
        >
          <X size={16} />
        </button>
      </div>
    </div>
  );
}
