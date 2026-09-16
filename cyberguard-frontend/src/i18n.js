import React, { createContext, useContext, useEffect, useRef } from 'react';

const translations = {
  OD: {
    'BPUT SOC / INNOVATION SUBMISSION': 'BPUT SOC / ନବସୃଜନ ପ୍ରଦର୍ଶନ',
    'AI SECURITY OPERATIONS CENTER': 'AI ସୁରକ୍ଷା ଅପରେସନ୍ସ କେନ୍ଦ୍ର',
    'CyberGuard AI': 'ସାଇବରଗାର୍ଡ AI',
    'Command Center': 'କମାଣ୍ଡ ସେଣ୍ଟର',
    'One operating picture for detection, explanation, and response across BPUT digital assets.': 'BPUT ଡିଜିଟାଲ ସମ୍ପଦ ପାଇଁ ଚିହ୍ନଟ, ବ୍ୟାଖ୍ୟା ଏବଂ ପ୍ରତିକ୍ରିୟାର ଏକୀକୃତ ଚିତ୍ର।',
    Posture: 'ସ୍ଥିତି',
    Operational: 'ସଚଳ',
    Checking: 'ଯାଞ୍ଚ ଚାଲିଛି',
    'Updated live from the AI engine': 'AI ଇଞ୍ଜିନ୍‌ରୁ ଲାଇଭ୍ ଅପଡେଟ୍',
    Dashboard: 'ଡ୍ୟାସବୋର୍ଡ',
    'Threat Feed': 'ବିପଦ ଫିଡ୍',
    'Threat Intelligence': 'ବିପଦ ସୂଚନା',
    Notifications: 'ବିଜ୍ଞପ୍ତି',
    Settings: 'ସେଟିଂସ୍',
    'System view': 'ସିଷ୍ଟମ୍ ଦୃଶ୍ୟ',
    'Runtime status': 'ରନ୍‌ଟାଇମ୍ ସ୍ଥିତି',
    'API Latency': 'API ବିଳମ୍ବ',
    'Model Confidence': 'ମଡେଲ୍ ବିଶ୍ୱସନୀୟତା',
    'Engine Throughput': 'ଇଞ୍ଜିନ୍ କ୍ଷମତା',
    'Threat Accuracy': 'ବିପଦ ସଠିକତା',
    'Priority detection coverage': 'ପ୍ରାଥମିକ ଚିହ୍ନଟ କଭରେଜ୍',
    'Upgrade engines': 'ଇଞ୍ଜିନ୍ ଅପଗ୍ରେଡ୍ କରନ୍ତୁ',
    'Overall risk posture': 'ସାମଗ୍ରିକ ବିପଦ ସ୍ଥିତି',
    'Live telemetry / event stream': 'ଲାଇଭ୍ ଟେଲିମେଟ୍ରି / ଇଭେଣ୍ଟ ଷ୍ଟ୍ରିମ୍',
    'Waiting for the first analyzed event.': 'ପ୍ରଥମ ବିଶ୍ଳେଷିତ ଇଭେଣ୍ଟ ପାଇଁ ଅପେକ୍ଷା କରାଯାଉଛି।',
    'Open detection workspace': 'ଚିହ୍ନଟ କାର୍ଯ୍ୟକ୍ଷେତ୍ର ଖୋଲନ୍ତୁ',
    'Privacy by design': 'ଡିଜାଇନ୍‌ରେ ଗୋପନୀୟତା',
    'Local-first analysis with restricted telemetry fallback.': 'ସୀମିତ ଟେଲିମେଟ୍ରି ସହିତ ସ୍ଥାନୀୟ-ପ୍ରଥମ ବିଶ୍ଳେଷଣ।',
    'Open Command View': 'କମାଣ୍ଡ ଦୃଶ୍ୟ ଖୋଲନ୍ତୁ',
    'REAL-TIME INTELLIGENCE ACTIVE': 'ରିଅଲ୍-ଟାଇମ୍ ଇଣ୍ଟେଲିଜେନ୍ସ ସକ୍ରିୟ',
    'ACTIVE SENSORS': 'ସକ୍ରିୟ ସେନ୍ସର',
    'THREAT MITIGATIONS': 'ବିପଦ ପ୍ରଶମନ',
    'SOC Login': 'SOC ଲଗଇନ୍',
    Authenticate: 'ପ୍ରାମାଣିକରଣ କରନ୍ତୁ',
    Cancel: 'ବାତିଲ୍ କରନ୍ତୁ',
    'Checking...': 'ଯାଞ୍ଚ ଚାଲିଛି...',
    'No notifications yet.': 'ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ବିଜ୍ଞପ୍ତି ନାହିଁ।',
    'Language': 'ଭାଷା',
  },
  HI: {
    'BPUT SOC / INNOVATION SUBMISSION': 'BPUT SOC / नवाचार प्रस्तुति',
    'AI SECURITY OPERATIONS CENTER': 'AI सुरक्षा संचालन केंद्र',
    'CyberGuard AI': 'साइबरगार्ड AI',
    'Command Center': 'कमांड सेंटर',
    'One operating picture for detection, explanation, and response across BPUT digital assets.': 'BPUT डिजिटल संपत्तियों में पहचान, व्याख्या और प्रतिक्रिया का एकीकृत दृश्य।',
    Posture: 'स्थिति',
    Operational: 'सक्रिय',
    Checking: 'जाँच जारी है',
    'Updated live from the AI engine': 'AI इंजन से लाइव अपडेट',
    Dashboard: 'डैशबोर्ड',
    'Threat Feed': 'खतरा फ़ीड',
    'Threat Intelligence': 'खतरा जानकारी',
    Notifications: 'सूचनाएँ',
    Settings: 'सेटिंग्स',
    'System view': 'सिस्टम दृश्य',
    'Runtime status': 'रनटाइम स्थिति',
    'API Latency': 'API विलंब',
    'Model Confidence': 'मॉडल विश्वसनीयता',
    'Engine Throughput': 'इंजन क्षमता',
    'Threat Accuracy': 'खतरा सटीकता',
    'Priority detection coverage': 'प्राथमिक पहचान कवरेज',
    'Upgrade engines': 'इंजन अपग्रेड करें',
    'Overall risk posture': 'समग्र जोखिम स्थिति',
    'Live telemetry / event stream': 'लाइव टेलीमेट्री / इवेंट स्ट्रीम',
    'Waiting for the first analyzed event.': 'पहली विश्लेषित घटना की प्रतीक्षा है।',
    'Open detection workspace': 'पहचान कार्यक्षेत्र खोलें',
    'Privacy by design': 'डिज़ाइन में गोपनीयता',
    'Local-first analysis with restricted telemetry fallback.': 'सीमित टेलीमेट्री के साथ स्थानीय-प्रथम विश्लेषण।',
    'Open Command View': 'कमांड दृश्य खोलें',
    'REAL-TIME INTELLIGENCE ACTIVE': 'रीयल-टाइम इंटेलिजेंस सक्रिय',
    'ACTIVE SENSORS': 'सक्रिय सेंसर',
    'THREAT MITIGATIONS': 'खतरा शमन',
    'SOC Login': 'SOC लॉगिन',
    Authenticate: 'प्रमाणित करें',
    Cancel: 'रद्द करें',
    'Checking...': 'जाँच जारी है...',
    'No notifications yet.': 'अभी कोई सूचना नहीं है।',
    Language: 'भाषा',
  },
};

const LanguageContext = createContext('EN');

function translateText(value, language) {
  if (language === 'EN') return value;
  const dictionary = translations[language];
  if (dictionary[value]) return dictionary[value];
  return value.replace(/[^.!?]+/g, (part) => dictionary[part.trim()] || part);
}

function translateDom(root, language, originals) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  let node;
  while ((node = walker.nextNode())) nodes.push(node);
  nodes.forEach((textNode) => {
    if (!textNode.nodeValue.trim() || textNode.parentElement?.closest('script, style, input, textarea')) return;
    if (!originals.has(textNode)) originals.set(textNode, textNode.nodeValue);
    textNode.nodeValue = translateText(originals.get(textNode), language);
  });
  root.querySelectorAll('[placeholder], [title], [aria-label]').forEach((element) => {
    ['placeholder', 'title', 'aria-label'].forEach((attribute) => {
      const value = element.getAttribute(attribute);
      if (value) {
        if (!element.dataset.originalLanguageText) element.dataset.originalLanguageText = value;
        element.setAttribute(attribute, translateText(element.dataset.originalLanguageText, language));
      }
    });
  });
}

export function LanguageProvider({ language, children }) {
  const originals = useRef(new WeakMap());

  useEffect(() => {
    const root = document.body;
    const update = () => translateDom(root, language, originals.current);
    update();
    const observer = new MutationObserver(update);
    observer.observe(root, { childList: true, subtree: true });
    document.documentElement.lang = language === 'OD' ? 'or' : language === 'HI' ? 'hi' : 'en';
    return () => observer.disconnect();
  }, [language]);

  return React.createElement(LanguageContext.Provider, { value: language }, children);
}

export function useLanguage() {
  return useContext(LanguageContext);
}