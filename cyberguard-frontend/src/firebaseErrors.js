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
    case 'auth/operation-not-allowed':
      return 'Google sign-in is not enabled for this Firebase project. Enable the Google provider in Firebase Authentication settings.';
    case 'auth/network-request-failed':
      return 'Could not reach Google/Firebase authentication. Check your internet connection and try again.';
    case 'auth/unauthorized-domain':
      return `This site is not authorized for Firebase sign-in. Add ${typeof window !== 'undefined' ? window.location.hostname : 'this domain'} to Firebase Authorized Domains.`;
    case 'auth/too-many-requests':
      return 'Access temporarily disabled due to many failed attempts. Try again later or reset password.';
    default:
      return error.message || 'Authentication failed. Please try again.';
  }
};
