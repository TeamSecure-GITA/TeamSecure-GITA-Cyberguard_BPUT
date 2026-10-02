// Import the functions you need from the SDKs you need
import { initializeApp, getApps, getApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// Your web app's Firebase configuration
export const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyDvKX-SLrFeCzPY_XxLCp6qtlmdvM0oiQc",
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "cyberguard-386d8.firebaseapp.com",
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "cyberguard-386d8",
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "cyberguard-386d8.firebasestorage.app",
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "477210292391",
  appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:477210292391:web:a149c190a2e6ff7d8a6b82",
  measurementId: import.meta.env.VITE_FIREBASE_MEASUREMENT_ID || "G-4ZFPFGMQZD"
};

// Initialize Firebase (safely reuse instance if already initialized)
export const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();

// Optional Firebase services for authentication and database
export const auth = getAuth(app);
export const db = getFirestore(app);

// Initialize Firebase Analytics safely (only in browser environments that support it)
export let analytics = null;
if (typeof window !== "undefined") {
  isSupported().then((supported) => {
    if (supported) {
      analytics = getAnalytics(app);
    }
  }).catch(() => {
    // Analytics not supported in current environment (e.g. ad blockers or non-browser)
  });
}

export default app;
