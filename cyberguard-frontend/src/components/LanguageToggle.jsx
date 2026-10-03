import React, { useState, useRef, useEffect } from 'react';
import { Globe, ChevronDown } from 'lucide-react';

export default function LanguageToggle({ currentLang = 'EN', onToggle, variant = 'default' }) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef(null);

  const languages = [
    { code: 'EN', label: 'English', sub: 'Default' },
    { code: 'OD', label: 'ଓଡ଼ିଆ', sub: 'Odia' },
    { code: 'HI', label: 'हिन्दी', sub: 'Hindi' }
  ];

  const currentObj = languages.find(l => l.code === currentLang) || languages[0];

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  if (variant === 'pill') {
    return (
      <div className="relative inline-block text-left" ref={dropdownRef}>
        <button
          type="button"
          onClick={() => setIsOpen(!isOpen)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-700/80 bg-slate-900/60 hover:bg-slate-800/80 text-xs font-mono text-slate-300 hover:text-white transition-all cursor-pointer"
          title="Change Language"
        >
          <Globe size={13} className="text-cyan-400" />
          <span className="font-semibold">{currentObj.code}</span>
          <ChevronDown size={12} className={`text-slate-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {isOpen && (
          <div className="absolute right-0 mt-2 w-36 rounded-xl bg-[#071729]/95 backdrop-blur-xl border border-cyan-500/30 shadow-[0_0_20px_rgba(6,182,212,0.25)] py-1 z-50 animate-in fade-in zoom-in-95 duration-150">
            {languages.map((lang) => (
              <button
                key={lang.code}
                onClick={() => {
                  onToggle(lang.code);
                  setIsOpen(false);
                }}
                className={`w-full px-3 py-1.5 text-left text-xs flex items-center justify-between transition-colors ${
                  currentLang === lang.code
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                }`}
              >
                <span>{lang.label}</span>
                <span className="font-mono text-[10px] text-slate-400">{lang.code}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center space-x-2 bg-slate-800/80 border border-slate-700/60 rounded-xl p-1">
      <Globe size={14} className="text-cyan-400 ml-1.5" />
      <div className="flex space-x-1">
        {languages.map((lang) => (
          <button
            key={lang.code}
            onClick={() => onToggle(lang.code)}
            className={`px-2 py-0.5 text-[10px] font-semibold rounded-md transition ${
              currentLang === lang.code
                ? 'bg-cyan-500 text-slate-950 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {lang.code}
          </button>
        ))}
      </div>
    </div>
  );
}