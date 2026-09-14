import React from 'react';
import { Languages } from 'lucide-react';

export default function LanguageToggle({ currentLang, onToggle }) {
  const languages = [
    { code: 'EN', label: 'English' },
    { code: 'OD', label: 'ଓଡ଼ିଆ (Odia)' },
    { code: 'HI', label: 'हिन्दी (Hindi)' }
  ];

  return (
    <div className="flex items-center space-x-2 bg-slate-800/80 border border-slate-700/60 rounded-xl p-1">
      <Languages size={16} className="text-slate-400 ml-2" />
      <div className="flex space-x-1">
        {languages.map((lang) => (
          <button
            key={lang.code}
            onClick={() => onToggle(lang.code)}
            className={`px-2.5 py-1 text-[11px] font-semibold rounded-lg transition ${
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