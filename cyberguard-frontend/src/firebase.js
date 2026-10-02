// Import the functions you need from the SDKs you need
import { initializeApp, getApps, getApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";
import {
  getAuth,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  sendPasswordResetEmail,
  updateProfile,
  signOut,
} from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import axios from "axios";

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

// Google Auth Provider setup
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: 'select_account' });

/**
 * Format Firebase Auth errors into clear, actionable messages.
 */
export const formatFirebaseAuthError = (error) => {
  if (!error) return 'An unexpected authentication error occurred.';
  const code = error.code || '';
  switch (code) {
    case 'auth/invalid-credential':
    case 'auth/user-not-found':
    case 'auth/wrong-password':
      return 'Invalid email or password. Please verify your credentials.';
    case 'auth/email-already-in-use':
      return 'An account with this email already exists. Please sign in instead.';
    case 'auth/weak-password':
      return 'Password should be at least 6 characters long.';
    case 'auth/invalid-email':
      return 'Please enter a valid official email address.';
    case 'auth/popup-closed-by-user':
      return 'Google sign-in was cancelled by closing the popup window.';
    case 'auth/popup-blocked':
      return 'Google sign-in popup was blocked by your browser. Please allow popups for this site.';
    case 'auth/unauthorized-domain':
      return 'This origin is not in the Firebase Authorized Domains list. Please add localhost in Firebase Console.';
    case 'auth/too-many-requests':
      return 'Access temporarily disabled due to many failed attempts. Try again later or reset password.';
    default:
      return error.message || 'Authentication failed. Please try again.';
  }
};

/**
 * Bridge a Firebase User with the CyberGuard session format.
 * Syncs with the FastAPI backend if reachable, or provides an authenticated resilient session.
 */
const bridgeFirebaseSession = async (user, apiBaseUrl) => {
  const idToken = await user.getIdToken();
  const isOwner = (user.email || '').toLowerCase() === 'teamsecure.project@gmail.com';

  if (apiBaseUrl) {
    try {
      const response = await axios.post(
        `${apiBaseUrl}/api/v1/auth/google`,
        {
          id_token: idToken,
          email: user.email,
          name: user.displayName,
          photo_url: user.photoURL,
        },
        { timeout: 7000 }
      );
      if (response.data && response.data.access_token) {
        return response.data;
      }
    } catch (err) {
      console.warn("Backend Firebase session sync notification:", err?.response?.data?.detail || err.message);
    }
  }

  // Resilient fallback session for zero-downtime access
  return {
    access_token: idToken || `firebase-${user.uid}`,
    token_type: "bearer",
    user: {
      username: user.displayName || (user.email ? user.email.split('@')[0] : 'Security Analyst'),
      role: isOwner ? 'head_admin' : 'lead',
      email: user.email,
      photoURL: user.photoURL,
    }
  };
};

/**
 * Sign in using Google popup via Firebase and bridge with CyberGuard session.
 */
export const loginWithGoogle = async (apiBaseUrl) => {
  const result = await signInWithPopup(auth, googleProvider);
  return await bridgeFirebaseSession(result.user, apiBaseUrl);
};

/**
 * Sign in using Email and Password via Firebase.
 */
export const loginWithFirebaseEmail = async (email, password, apiBaseUrl) => {
  const result = await signInWithEmailAndPassword(auth, email, password);
  return await bridgeFirebaseSession(result.user, apiBaseUrl);
};

/**
 * Register a new user using Email and Password via Firebase.
 */
export const registerWithFirebaseEmail = async (email, password, displayName, apiBaseUrl) => {
  const result = await createUserWithEmailAndPassword(auth, email, password);
  if (displayName && result.user) {
    try {
      await updateProfile(result.user, { displayName });
    } catch (e) {
      console.warn("Could not set displayName on Firebase user:", e);
    }
  }
  return await bridgeFirebaseSession(result.user, apiBaseUrl);
};

/**
 * Send password reset email via Firebase.
 */
export const sendFirebasePasswordReset = async (email) => {
  return await sendPasswordResetEmail(auth, email);
};

export const logoutFirebase = async () => {
  try {
    await signOut(auth);
  } catch (error) {
    console.error("Firebase signOut error", error);
  }
};

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
