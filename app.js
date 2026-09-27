const modal = document.querySelector('#composerModal');
const toast = document.querySelector('#toast');
const feed = document.querySelector('#feed');
const authModal = document.querySelector('#authModal');
const authState = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
let authMode = 'login';

let firebaseApp = null;
let firebaseAuth = null;
let firestore = null;
let phoneConfirmation = null;
let pendingSignup = null;
let phoneRecaptcha = null;

const AUTH_PROVIDER = 'firebase';
const AUTH_PROVIDERS = {
  firebase: { label: 'Firebase', enabled: true },
  clerk: { label: 'Clerk', enabled: true },
  auth0: { label: 'Auth0', enabled: true },
};
const SECURITY_LIMITS = {
  maxAttempts: 5,
  lockWindowMs: 10 * 60 * 1000,
  minPasswordLength: 8,
  maxPasswordLength: 128,
  maxNameLength: 40,
  maxIdentityLength: 120,
};
const SUSPICIOUS_PATTERNS = [/<\s*script/i, /javascript:/i, /\b(drop|delete|alter|union)\b/i, /\b(or|and)\s+\d+=\d+/i];

function genericAuthError() {
  return 'We could not complete that request. Please check your details and try again.';
}

function sanitizeInput(value, maxLength = 120) {
  return String(value ?? '').replace(/[<>]/g, '').trim().slice(0, maxLength);
}

function isSuspicious(value) {
  return SUSPICIOUS_PATTERNS.some((pattern) => pattern.test(String(value ?? '')));
}

function getSecurityStore() {
  try {
    return JSON.parse(localStorage.getItem('aikya-security') || '{}');
  } catch {
    return {};
  }
}

function saveSecurityStore(store) {
  localStorage.setItem('aikya-security', JSON.stringify(store));
}

function getRateLimitKey(identity) {
  return String(identity || '').trim().toLowerCase();
}

function isLoginRateLimited(identity) {
  const key = getRateLimitKey(identity);
  if (!key) return false;
  const store = getSecurityStore();
  const entry = store[key] || { attempts: 0, lockUntil: 0 };
  const now = Date.now();
  if (entry.lockUntil && now < entry.lockUntil) return true;
  if (entry.attempts >= SECURITY_LIMITS.maxAttempts && now - (entry.lastAttempt || 0) < SECURITY_LIMITS.lockWindowMs) {
    store[key] = { attempts: entry.attempts, lastAttempt: entry.lastAttempt || now, lockUntil: now + SECURITY_LIMITS.lockWindowMs };
    saveSecurityStore(store);
    return true;
  }
  return false;
}

function recordFailedAttempt(identity) {
  const key = getRateLimitKey(identity);
  const store = getSecurityStore();
  const entry = store[key] || { attempts: 0, lastAttempt: 0, lockUntil: 0 };
  const now = Date.now();
  const attempts = entry.lockUntil && now < entry.lockUntil ? SECURITY_LIMITS.maxAttempts : entry.attempts + 1;
  store[key] = {
    attempts,
    lastAttempt: now,
    lockUntil: attempts >= SECURITY_LIMITS.maxAttempts ? now + SECURITY_LIMITS.lockWindowMs : 0,
  };
  saveSecurityStore(store);
}

function clearFailedAttempts(identity) {
  const key = getRateLimitKey(identity);
  const store = getSecurityStore();
  delete store[key];
  saveSecurityStore(store);
}

function validateServerInput({ name, identity, password }) {
  const issues = [];
  if (name && name.length > SECURITY_LIMITS.maxNameLength) issues.push('Name too long.');
  if (identity && identity.length > SECURITY_LIMITS.maxIdentityLength) issues.push('Identity too long.');
  if (password && (password.length < SECURITY_LIMITS.minPasswordLength || password.length > SECURITY_LIMITS.maxPasswordLength)) issues.push('Password length invalid.');
  if (name && isSuspicious(name)) issues.push('Invalid characters in name.');
  if (identity && isSuspicious(identity)) issues.push('Invalid characters in identity.');
  if (password && isSuspicious(password)) issues.push('Invalid characters in password.');
  return issues;
}

function getPasswordHashConfig() {
  return {
    name: 'PBKDF2',
    iterations: 250000,
    hash: 'SHA-256',
    saltLength: 16,
  };
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(getPasswordHashConfig().saltLength));
  const encodedPassword = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', encodedPassword, 'PBKDF2', false, ['deriveBits']);
  const hashBuffer = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt,
    iterations: getPasswordHashConfig().iterations,
    hash: getPasswordHashConfig().hash,
  }, baseKey, 256);
  const hash = Array.from(new Uint8Array(hashBuffer)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return {
    hash,
    salt: Array.from(salt).map((byte) => byte.toString(16).padStart(2, '0')).join(''),
  };
}

async function verifyPassword(password, userRecord) {
  if (!userRecord) return false;
  if (userRecord.passwordHash && userRecord.salt) {
    const saltBytes = Uint8Array.from(userRecord.salt.match(/.{1,2}/g).map((part) => Number.parseInt(part, 16)));
    const encodedPassword = new TextEncoder().encode(password);
    const baseKey = await crypto.subtle.importKey('raw', encodedPassword, 'PBKDF2', false, ['deriveBits']);
    const hashBuffer = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: getPasswordHashConfig().iterations,
      hash: getPasswordHashConfig().hash,
    }, baseKey, 256);
    const candidate = Array.from(new Uint8Array(hashBuffer)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
    return candidate === userRecord.passwordHash;
  }
  return userRecord.password === password;
}

function initializeFirebaseBackend() {
  if (!window.firebase || !window.AIKYA_FIREBASE_CONFIG) return null;
  const config = window.AIKYA_FIREBASE_CONFIG || {};
  const hasValidConfig = config.apiKey && config.apiKey !== 'YOUR_API_KEY' && config.projectId && config.projectId !== 'YOUR_PROJECT_ID';
  if (!hasValidConfig) return null;

  if (!firebaseApp) {
    firebaseApp = firebase.initializeApp(config);
    firebaseAuth = firebase.auth();
    firestore = firebase.firestore();
  }

  return { firebaseApp, firebaseAuth, firestore };
}

function isFirebaseReady() {
  return !!initializeFirebaseBackend();
}

function getUsers() {
  try {
    return JSON.parse(localStorage.getItem('aikya-users') || '{}');
  } catch {
    return {};
  }
}

function saveUsers(users) {
  localStorage.setItem('aikya-users', JSON.stringify(users));
}

function saveAuth(user) {
  const safeUser = { ...user };
  delete safeUser.password;
  delete safeUser.passwordHash;
  delete safeUser.salt;
  localStorage.setItem('aikya-auth', JSON.stringify(safeUser));
}

function getAuthProviderHint() {
  const providerNames = Object.keys(AUTH_PROVIDERS).join(', ');
  return `Auth provider ready for ${providerNames}. For production, wire one provider to a real backend.`;
}

function loadAuthProvider() {
  const provider = AUTH_PROVIDER.toLowerCase();
  if (!AUTH_PROVIDERS[provider]) return null;
  return { provider, label: AUTH_PROVIDERS[provider].label };
}

function updateAccountUi() {
  const user = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
  const label = document.querySelector('.account-label');
  const avatar = document.querySelector('.account-avatar');
  label.textContent = user ? user.name : 'Sign in';
  avatar.textContent = user ? user.name.charAt(0).toUpperCase() : 'S';
  document.querySelector('.mini-profile strong').textContent = user?.name || 'Sohail';
  document.querySelector('.mini-profile span').textContent = user ? `@${user.username}` : '@sohailcreates';
}

function openAuth(view = 'guest') {
  authModal.classList.add('open');
  authModal.setAttribute('aria-hidden', 'false');
  document.querySelector('#authGuest').classList.toggle('hidden', view !== 'guest');
  document.querySelector('#authReset').classList.toggle('hidden', view !== 'reset');
  document.querySelector('#authUser').classList.toggle('hidden', view !== 'user');
  if (view === 'user') {
    const user = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
    document.querySelector('#profileHeading').textContent = user?.name || 'Your profile';
    document.querySelector('#profileName').value = user?.name || '';
    document.querySelector('#profileUsername').value = user?.username || '';
    document.querySelector('#profileBio').value = user?.bio || '';
    document.querySelector('#profileAvatar').textContent = (user?.name || 'S').charAt(0).toUpperCase();
    const settings = user?.settings || {};
    document.querySelector('#settingNotifications').checked = settings.notifications !== false;
    document.querySelector('#settingPrivate').checked = settings.private === true;
    document.querySelector('#settingAutoplay').checked = settings.autoplay !== false;
  }
}

updateAccountUi();

function setupAuthControls() {
  const passwordInput = document.querySelector('#authPassword');
  if (!passwordInput || document.querySelector('#togglePassword')) return;
  const passwordWrap = document.createElement('span');
  passwordWrap.className = 'password-field';
  passwordInput.parentNode.insertBefore(passwordWrap, passwordInput);
  passwordWrap.append(passwordInput);
  const toggle = document.createElement('button');
  toggle.type = 'button';
  toggle.id = 'togglePassword';
  toggle.className = 'password-toggle';
  toggle.textContent = 'Show';
  toggle.setAttribute('aria-label', 'Show password');
  passwordWrap.append(toggle);
  toggle.addEventListener('click', () => {
    const visible = passwordInput.type === 'text';
    passwordInput.type = visible ? 'password' : 'text';
    toggle.textContent = visible ? 'Show' : 'Hide';
    toggle.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
  });
  const form = document.querySelector('#authForm');
  const recaptcha = document.createElement('div');
  recaptcha.id = 'recaptcha-container';
  form.insertBefore(recaptcha, form.querySelector('.auth-submit'));
  const verification = document.createElement('div');
  verification.id = 'authVerification';
  verification.className = 'auth-verification hidden';
  verification.innerHTML = '<strong>Verify your account</strong><span id="verificationMessage">Enter the code sent to your phone.</span><input id="verificationCode" inputmode="numeric" autocomplete="one-time-code" placeholder="Verification code"><button class="auth-submit" id="verifyAccount" type="button">Verify and create account</button>';
  form.after(verification);
  verification.querySelector('#verifyAccount').addEventListener('click', verifyPhoneSignup);
  const style = document.createElement('style');
  style.textContent = '.password-field{display:flex;gap:8px;align-items:center}.password-field input{min-width:0;flex:1}.password-toggle{border:1px solid #d7e1de;border-radius:7px;background:#fff;color:#29444a;padding:10px 11px;font-size:12px;font-weight:700;cursor:pointer}.auth-verification{display:grid;gap:8px;margin-top:12px;padding:12px;border:1px solid #c9ddd7;border-radius:10px;background:#f7fbfa}.auth-verification span{font-size:12px;color:#617476}.auth-verification input{width:100%;box-sizing:border-box;border:1px solid #d7e1de;border-radius:7px;padding:11px;font-size:14px;letter-spacing:2px}';
  document.head.append(style);
}

setupAuthControls();

const settingsList = document.querySelector('.settings-list');
settingsList.innerHTML = `<p class="settings-group-title">Privacy & account</p><label class="setting-row"><span>Private account<small>Only approved people can follow you</small></span><input type="checkbox" id="settingPrivate"></label><label class="setting-row"><span>Activity status<small>Show when you are active</small></span><input type="checkbox" id="settingActivity" checked></label><label class="setting-row"><span>Read receipts<small>Let people know when you read messages</small></span><input type="checkbox" id="settingReceipts" checked></label><p class="settings-group-title">Notifications</p><label class="setting-row"><span>Push notifications<small>Likes, follows and messages</small></span><input type="checkbox" id="settingNotifications" checked></label><label class="setting-row"><span>Email updates<small>Occasional news from AiKya</small></span><input type="checkbox" id="settingEmail"></label><p class="settings-group-title">Experience</p><label class="setting-row"><span>Autoplay clips<small>Play videos while scrolling</small></span><input type="checkbox" id="settingAutoplay" checked></label><label class="setting-row"><span>Data saver<small>Use less mobile data</small></span><input type="checkbox" id="settingDataSaver"></label><label class="setting-row"><span>Dark appearance<small>Use a darker workspace</small></span><input type="checkbox" id="settingDark"></label><label class="setting-select"><span>Language</span><select id="settingLanguage"><option value="en">English</option><option value="hi">Hindi</option><option value="hinglish">Hinglish</option></select></label><p class="settings-group-title">Safety & data</p><button class="settings-action" id="blockedAccounts">Blocked accounts <span>›</span></button><button class="settings-action" id="downloadData">Download my data <span>›</span></button><button class="settings-action danger" id="deleteAccount">Delete account <span>›</span></button>`;
const settingsSave = document.createElement('button');
settingsSave.className = 'auth-submit';
settingsSave.id = 'saveSettings';
settingsSave.textContent = 'Save settings';
settingsList.after(settingsSave);
document.querySelector('#openAccount').addEventListener('click', () => openAuth(localStorage.getItem('aikya-auth') ? 'user' : 'guest'));
document.querySelectorAll('[data-close-auth]').forEach((button) => button.addEventListener('click', () => authModal.classList.remove('open')));
document.querySelectorAll('[data-auth-mode]').forEach((button) => button.addEventListener('click', () => {
  authMode = button.dataset.authMode;
  document.querySelectorAll('.auth-tab').forEach((tab) => tab.classList.toggle('active', tab === button));
  document.querySelector('#authTitle').textContent = authMode === 'signup' ? 'Create your AiKya account' : 'Log in to AiKya';
  document.querySelector('#authNameWrap').classList.toggle('hidden', authMode !== 'signup');
  document.querySelector('.auth-submit').textContent = authMode === 'signup' ? 'Create account' : 'Log in';
  document.querySelector('#authVerification')?.classList.add('hidden');
}));
document.querySelector('#forgotPassword').addEventListener('click', () => openAuth('reset'));
document.querySelector('#backToLogin').addEventListener('click', () => openAuth('guest'));
document.querySelector('#authForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const identity = sanitizeInput(document.querySelector('#authIdentity').value, SECURITY_LIMITS.maxIdentityLength).toLowerCase();
  const password = sanitizeInput(document.querySelector('#authPassword').value, SECURITY_LIMITS.maxPasswordLength);
  const name = sanitizeInput(document.querySelector('#authName').value || 'AiKya User', SECURITY_LIMITS.maxNameLength) || 'AiKya User';
  const users = getUsers();
  const provider = loadAuthProvider();

  if (!identity || !password) return showToast(genericAuthError());
  if (isLoginRateLimited(identity)) return showToast('Too many login attempts. Please try again later.');

  const validationIssues = validateServerInput({ name, identity, password });
  if (validationIssues.length) return showToast(genericAuthError());

  const firebaseReady = isFirebaseReady();

  if (authMode === 'signup') {
    if (!identity.includes('@') && !/^\+?[0-9 ()-]{8,}$/.test(identity)) return showToast(genericAuthError());
    if (users[identity]) return showToast(genericAuthError());

    if (!firebaseReady) return showToast('Account creation requires Firebase verification. Add your Firebase config first.');
    if (!identity.includes('@')) {
      try {
        if (!phoneRecaptcha) phoneRecaptcha = new firebase.auth.RecaptchaVerifier('recaptcha-container', { size: 'invisible' });
        phoneConfirmation = await firebaseAuth.signInWithPhoneNumber(identity.replace(/[ ()-]/g, ''), phoneRecaptcha);
        pendingSignup = { identity, name, password };
        document.querySelector('#verificationMessage').textContent = `Enter the SMS code sent to ${identity}.`;
        document.querySelector('#authVerification').classList.remove('hidden');
        showToast('Verification code sent by SMS.');
      } catch (error) {
        console.error('Firebase phone verification failed', error);
        phoneRecaptcha?.clear();
        phoneRecaptcha = null;
        showToast(genericAuthError());
      }
      return;
    }
    try {
      const response = await firebaseAuth.createUserWithEmailAndPassword(identity, password);
      await response.user.sendEmailVerification();
      await firebaseAuth.signOut();
      pendingSignup = { identity, name, password };
      document.querySelector('#verificationMessage').textContent = `Verification email sent to ${identity}. Verify it, then log in to finish setup.`;
      document.querySelector('#authVerification').classList.remove('hidden');
      showToast('Check your email to verify this account.');
    } catch (error) {
      console.error('Firebase signup failed', error);
      showToast(genericAuthError());
    }
  } else {
    if (!firebaseReady) return showToast('Login is temporarily unavailable. Firebase is not configured.');
    try {
        const response = await firebaseAuth.signInWithEmailAndPassword(identity, password);
        if (response.user.email && !response.user.emailVerified) {
          await response.user.sendEmailVerification();
          await firebaseAuth.signOut();
          return showToast('Verify your email first. A new verification email was sent.');
        }
        const userDoc = await firestore.collection('users').doc(response.user.uid).get();
        const userData = userDoc.data() || {};
        const safeUser = {
          uid: response.user.uid,
          name: userData.name || response.user.email,
          username: userData.username || 'aikyafriend',
          identity: response.user.email,
          bio: userData.bio || '',
          provider: AUTH_PROVIDER,
        };
        saveAuth(safeUser);
        clearFailedAttempts(identity);
        updateAccountUi();
        openAuth('user');
        showToast('Welcome back to AiKya.');
        return;
      } catch (error) {
        console.error('Firebase login failed', error);
        recordFailedAttempt(identity);
        return showToast(genericAuthError());
      }
  }
});
async function verifyPhoneSignup() {
  if (!pendingSignup || !phoneConfirmation) return showToast('Start account creation again.');
  const code = document.querySelector('#verificationCode').value.trim();
  if (!/^\d{6}$/.test(code)) return showToast('Enter the 6-digit verification code.');
  try {
    const response = await phoneConfirmation.confirm(code);
    const user = response.user;
    const username = pendingSignup.name.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(0, 18) || 'aikyafriend';
    await firestore.collection('users').doc(user.uid).set({ uid: user.uid, name: pendingSignup.name, username, phone: pendingSignup.identity, createdAt: firebase.firestore.FieldValue.serverTimestamp(), provider: AUTH_PROVIDER });
    saveAuth({ uid: user.uid, name: pendingSignup.name, username, identity: pendingSignup.identity, bio: '' });
    clearFailedAttempts(pendingSignup.identity);
    pendingSignup = null;
    phoneConfirmation = null;
    updateAccountUi();
    openAuth('user');
    showToast('Phone verified. Account created successfully.');
  } catch (error) {
    console.error('Firebase OTP verification failed', error);
    showToast(genericAuthError());
  }
}
document.querySelector('#resetForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const identity = sanitizeInput(document.querySelector('#resetIdentity').value, SECURITY_LIMITS.maxIdentityLength).toLowerCase();
  if (!identity || !identity.includes('@') || !isFirebaseReady()) return showToast(genericAuthError());
  try {
    await firebaseAuth.sendPasswordResetEmail(identity);
    showToast('If that account exists, a reset email has been sent.');
    openAuth('guest');
  } catch (error) {
    console.error('Firebase password reset failed', error);
    showToast('If that account exists, a reset email has been sent.');
  }
});
document.querySelector('#saveProfile').addEventListener('click', () => {
  const user = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
  if (!user) return;
  const candidateName = sanitizeInput(document.querySelector('#profileName').value || user.name, SECURITY_LIMITS.maxNameLength);
  const candidateUsername = sanitizeInput(document.querySelector('#profileUsername').value || user.username, 24).replace(/^@/, '');
  const candidateBio = sanitizeInput(document.querySelector('#profileBio').value || user.bio, 220);
  if (isSuspicious(candidateName) || isSuspicious(candidateUsername) || isSuspicious(candidateBio)) return showToast(genericAuthError());
  user.name = candidateName || user.name;
  user.username = candidateUsername || user.username;
  user.bio = candidateBio;
  user.settings = { ...user.settings, notifications: document.querySelector('#settingNotifications').checked, private: document.querySelector('#settingPrivate').checked, autoplay: document.querySelector('#settingAutoplay').checked };
  const users = getUsers();
  users[user.identity] = user;
  saveUsers(users); saveAuth(user); updateAccountUi(); showToast('Profile updated.');
});
document.querySelector('#saveSettings').addEventListener('click', () => {
  const user = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
  if (!user) return showToast('Log in to save settings.');
  user.settings = { notifications: document.querySelector('#settingNotifications').checked, private: document.querySelector('#settingPrivate').checked, activity: document.querySelector('#settingActivity').checked, receipts: document.querySelector('#settingReceipts').checked, email: document.querySelector('#settingEmail').checked, autoplay: document.querySelector('#settingAutoplay').checked, dataSaver: document.querySelector('#settingDataSaver').checked, dark: document.querySelector('#settingDark').checked, language: document.querySelector('#settingLanguage').value };
  const users = JSON.parse(localStorage.getItem('aikya-users') || '{}');
  users[user.identity] = user;
  localStorage.setItem('aikya-users', JSON.stringify(users)); saveAuth(user);
  document.body.classList.toggle('dark-mode', user.settings.dark);
  showToast('All settings saved.');
});
document.querySelector('#blockedAccounts').addEventListener('click', () => showToast('No blocked accounts.'));
document.querySelector('#downloadData').addEventListener('click', () => {
  const data = { account: JSON.parse(localStorage.getItem('aikya-auth') || 'null'), posts: savedPosts, settings: JSON.parse(localStorage.getItem('aikya-state') || '{}') };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'aikya-data.json'; link.click(); URL.revokeObjectURL(link.href); showToast('Your data download started.');
});
document.querySelector('#deleteAccount').addEventListener('click', () => {
  const user = JSON.parse(localStorage.getItem('aikya-auth') || 'null');
  if (!user || !window.confirm('Delete this local AiKya account and profile?')) return;
  const users = JSON.parse(localStorage.getItem('aikya-users') || '{}'); delete users[user.identity];
  localStorage.setItem('aikya-users', JSON.stringify(users)); localStorage.removeItem('aikya-auth'); updateAccountUi(); authModal.classList.remove('open'); showToast('Account deleted from this device.');
});
document.querySelector('#logoutButton').addEventListener('click', () => { localStorage.removeItem('aikya-auth'); updateAccountUi(); authModal.classList.remove('open'); showToast('You are logged out.'); });

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove('show'), 2200);
}

document.querySelector('#openComposer').addEventListener('click', () => {
  modal.classList.add('open');
  modal.setAttribute('aria-hidden', 'false');
  document.querySelector('#postText').focus();
});
document.querySelectorAll('[data-close-modal]').forEach((button) => button.addEventListener('click', () => {
  modal.classList.remove('open');
  modal.setAttribute('aria-hidden', 'true');
}));

const savedPosts = JSON.parse(localStorage.getItem('aikya-posts') || '[]');
const savedState = JSON.parse(localStorage.getItem('aikya-state') || '{}');
const persistState = () => localStorage.setItem('aikya-state', JSON.stringify(savedState));
const persistPosts = () => localStorage.setItem('aikya-posts', JSON.stringify(savedPosts));
const mediaLibrary = [
  { id: 'flower-film', type: 'video', title: 'Spring in motion', creator: 'AiKya Nature', category: 'Video', media: 'https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4', text: 'A calm nature film for a quiet break. video nature flower film' },
  { id: 'big-buck-bunny', type: 'movie', title: 'Big Buck Bunny', creator: 'Open Movie Project', category: 'Movie', media: 'https://storage.googleapis.com/coverr-main/mp4/Mt_Baker.mp4', text: 'Featured open movie and independent film. movie animation film' },
  { id: 'city-stories', type: 'video', title: 'City stories', creator: 'AiKya Watch', category: 'Video', media: 'https://www.w3schools.com/html/mov_bbb.mp4', text: 'A short city video to watch and share. video city travel' },
];
const TMDB_API_BASE = 'https://api.themoviedb.org/3';
const TMDB_IMAGE_BASE = 'https://image.tmdb.org/t/p/w500';
let activeMovieCategory = 'movie';
let movieSearchTimer;
let movieRequestId = 0;

function tmdbIsConfigured() {
  return Boolean(window.AIKYA_TMDB_API_KEY && window.AIKYA_TMDB_API_KEY !== 'YOUR_TMDB_API_KEY');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

function movieCatalogMarkup(category) {
  const categories = [
    ['movie', 'Movies'],
    ['tv', 'TV Shows'],
    ['animation', 'Animation'],
  ];
  return `<section class="movie-catalog" aria-label="Movie and TV discovery"><div class="movie-catalog-top"><div><p class="eyebrow">Discover</p><h2>Stories to watch</h2></div><label class="movie-search-wrap"><span aria-hidden="true">⌕</span><input class="movie-search" type="search" placeholder="Search titles" aria-label="Search movies and shows"></label></div><div class="movie-categories" role="tablist" aria-label="Content type">${categories.map(([value, label]) => `<button class="movie-category ${category === value ? 'active' : ''}" type="button" role="tab" aria-selected="${category === value}" data-category="${value}">${label}</button>`).join('')}</div><div class="movie-results" aria-live="polite"></div><p class="tmdb-attribution">Movie and TV information provided by <a href="https://www.themoviedb.org/" target="_blank" rel="noopener">TMDB</a>. AiKya is not endorsed or certified by TMDB.</p></section>`;
}

async function fetchTmdb(path, params = {}) {
  const url = new URL(`${TMDB_API_BASE}${path}`);
  url.search = new URLSearchParams({ api_key: window.AIKYA_TMDB_API_KEY, language: 'en-US', include_adult: 'false', ...params }).toString();
  const response = await fetch(url);
  if (!response.ok) throw new Error(`TMDB request failed (${response.status})`);
  return response.json();
}

function createMovieCard(item, mediaType) {
  const title = item.title || item.name || 'Untitled';
  const date = item.release_date || item.first_air_date || '';
  const card = document.createElement('article');
  card.className = 'movie-card';
  const poster = document.createElement('img');
  poster.className = 'movie-poster';
  poster.alt = `${title} poster`;
  poster.loading = 'lazy';
  if (item.poster_path) poster.src = `${TMDB_IMAGE_BASE}${item.poster_path}`;
  else poster.classList.add('poster-missing');
  poster.addEventListener('error', () => poster.classList.add('poster-missing'), { once: true });

  const details = document.createElement('div');
  details.className = 'movie-details';
  const heading = document.createElement('h3');
  heading.textContent = title;
  const meta = document.createElement('p');
  meta.className = 'movie-meta';
  meta.textContent = [mediaType === 'tv' ? 'TV show' : 'Movie', date.slice(0, 4), item.vote_average ? `★ ${Number(item.vote_average).toFixed(1)}` : ''].filter(Boolean).join(' · ');
  const overview = document.createElement('p');
  overview.className = 'movie-overview';
  overview.textContent = item.overview || 'No description available.';
  const watchLink = document.createElement('a');
  watchLink.className = 'movie-watch-link';
  watchLink.href = `https://www.justwatch.com/in/search?q=${encodeURIComponent(title)}`;
  watchLink.target = '_blank';
  watchLink.rel = 'noopener noreferrer';
  watchLink.textContent = 'Find where to watch';
  details.append(heading, meta, overview, watchLink);
  card.append(poster, details);
  return card;
}

async function loadMovieResults(catalog, query = '') {
  const results = catalog.querySelector('.movie-results');
  const requestId = ++movieRequestId;
  results.innerHTML = '<p class="movie-status">Loading titles...</p>';
  if (!tmdbIsConfigured()) {
    results.innerHTML = '<div class="movie-status movie-setup"><strong>Catalog setup needed</strong><span>Add a TMDB API key to <code>AiKya/firebase-config.js</code> as <code>AIKYA_TMDB_API_KEY</code> to load current movie and TV listings.</span><a href="https://www.themoviedb.org/settings/api" target="_blank" rel="noopener">Get a TMDB API key</a></div>';
    return;
  }

  try {
    let items = [];
    if (activeMovieCategory === 'animation') {
      const requests = ['movie', 'tv'].map(async (type) => {
        const data = query
          ? await fetchTmdb(`/search/${type}`, { query, page: '1' })
          : await fetchTmdb(`/discover/${type}`, { with_genres: '16', sort_by: 'popularity.desc', page: '1' });
        return (data.results || []).filter((item) => !query || item.genre_ids?.includes(16)).map((item) => ({ ...item, media_type: type }));
      });
      items = (await Promise.all(requests)).flat().sort((left, right) => (right.popularity || 0) - (left.popularity || 0)).slice(0, 20);
    } else {
      const endpoint = query ? `/search/${activeMovieCategory}` : `/discover/${activeMovieCategory}`;
      const data = await fetchTmdb(endpoint, query ? { query, page: '1' } : { sort_by: 'popularity.desc', page: '1' });
      items = (data.results || []).map((item) => ({ ...item, media_type: activeMovieCategory }));
    }

    if (requestId !== movieRequestId || !catalog.isConnected) return;
    results.replaceChildren();
    if (!items.length) {
      results.innerHTML = `<p class="movie-status">No ${escapeHtml(activeMovieCategory === 'tv' ? 'shows' : 'titles')} found. Try another search.</p>`;
      return;
    }
    const grid = document.createElement('div');
    grid.className = 'movie-grid';
    items.forEach((item) => grid.append(createMovieCard(item, item.media_type)));
    results.append(grid);
  } catch (error) {
    console.error('TMDB catalog request failed', error);
    if (requestId === movieRequestId && catalog.isConnected) {
      results.innerHTML = '<p class="movie-status">Could not load the catalog. Check the API key and internet connection, then try again.</p><button class="movie-retry" type="button">Retry</button>';
      results.querySelector('.movie-retry').addEventListener('click', () => loadMovieResults(catalog, query));
    }
  }
}

function renderMovieCatalog(category = activeMovieCategory) {
  activeMovieCategory = category;
  document.querySelector('.movie-catalog')?.remove();
  document.querySelectorAll('.media-library-post, .media-empty').forEach((item) => item.remove());
  document.querySelectorAll('.post').forEach((post) => post.classList.add('hidden'));
  feed.insertAdjacentHTML('afterbegin', movieCatalogMarkup(category));
  const catalog = feed.querySelector('.movie-catalog');
  catalog.querySelectorAll('.movie-category').forEach((button) => button.addEventListener('click', () => {
    activeMovieCategory = button.dataset.category;
    catalog.querySelectorAll('.movie-category').forEach((tab) => {
      const selected = tab === button;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
    });
    loadMovieResults(catalog, catalog.querySelector('.movie-search').value.trim());
  }));
  catalog.querySelector('.movie-search').addEventListener('input', (event) => {
    clearTimeout(movieSearchTimer);
    movieSearchTimer = setTimeout(() => loadMovieResults(catalog, event.target.value.trim()), 350);
  });
  loadMovieResults(catalog);
}

function postMarkup(data) {
  const imageTypes = ['image'];
  const videoTypes = ['video', 'reel', 'movie'];
  const media = imageTypes.includes(data.type) && data.media ? `<img class="media-preview" src="${data.media}" alt="User shared photo" onerror="this.remove()">` : videoTypes.includes(data.type) && data.media ? `<video class="media-preview video-preview" src="${data.media}" controls playsinline></video>` : '';
  return `<div class="post-header"><div class="avatar avatar-self">S</div><div class="post-author"><strong>Sohail</strong><span>@sohailcreates · ${data.time || 'just now'}</span></div><button class="post-menu">•••</button></div><p class="post-copy"></p>${media}<div class="post-footer"><div class="post-actions"><button class="action like-button"><span>♡</span><b>${data.likes || 0}</b></button><button class="action comment-button"><span>◌</span><b>${data.comments || 0}</b></button><button class="action share-button"><span>↗</span><b>0</b></button></div><button class="action save-button"><span>▱</span></button></div>`;
}

function addPost(data, prepend = true) {
  const post = document.createElement('article');
  post.className = 'post';
  post.dataset.search = `${data.text} ${data.type}`.toLowerCase();
  post.dataset.type = data.type;
  post.innerHTML = postMarkup(data);
  post.querySelector('.post-copy').textContent = data.text;
  if (savedState[`saved-${data.id}`]) post.querySelector('.save-button')?.classList.add('saved');
  if (prepend) feed.prepend(post); else feed.append(post);
  bindPostActions(post, data.id);
}

function isSignedIn() {
  return Boolean(JSON.parse(localStorage.getItem('aikya-auth') || 'null'));
}

function renderMediaLibrary(kind = 'all', query = '') {
  document.querySelectorAll('.media-library-post').forEach((post) => post.remove());
  const normalizedQuery = query.toLowerCase();
  const mediaItems = mediaLibrary.filter((item) => {
    const kindMatches = kind === 'all' || (kind === 'movies' ? item.type === 'movie' : item.type === 'video');
    const queryMatches = !normalizedQuery || `${item.title} ${item.creator} ${item.category} ${item.text}`.toLowerCase().includes(normalizedQuery);
    return kindMatches && queryMatches;
  });
  mediaItems.reverse().forEach((item) => {
    const mediaPost = document.createElement('article');
    mediaPost.className = 'post media-library-post';
    mediaPost.dataset.search = `${item.title} ${item.creator} ${item.category} ${item.text}`.toLowerCase();
    mediaPost.dataset.type = item.type;
    mediaPost.innerHTML = postMarkup({ ...item, time: 'AiKya library', likes: 0, comments: 0 });
    mediaPost.querySelector('.post-copy').textContent = `${item.title} · ${item.creator}`;
    feed.prepend(mediaPost);
    bindPostActions(mediaPost, item.id);
  });
  if (!mediaItems.length) {
    const empty = document.createElement('div');
    empty.className = 'media-empty';
    empty.innerHTML = `<strong>No videos found in AiKya yet.</strong><span>Try another title or search the web for more.</span><button class="auth-submit media-web-search">Search the web</button>`;
    feed.prepend(empty);
    empty.querySelector('.media-web-search').addEventListener('click', () => {
      const search = query || (kind === 'movies' ? 'movies' : 'videos');
      window.open(`https://www.youtube.com/results?search_query=${encodeURIComponent(search)}`, '_blank', 'noopener');
    });
  }
}

savedPosts.forEach((post) => addPost(post, false));
document.body.classList.toggle('dark-mode', JSON.parse(localStorage.getItem('aikya-auth') || 'null')?.settings?.dark === true);

document.querySelector('#publishPost').addEventListener('click', () => {
  const text = document.querySelector('#postText').value.trim();
  const type = document.querySelector('#postType').value;
  const media = document.querySelector('#mediaUrl').value.trim();
  const file = document.querySelector('#mediaFile').files[0];
  if (!text) return showToast('Write something before posting.');
  if (type !== 'text' && !media && !file) return showToast('Choose a media file or add a URL.');
  const savePost = (mediaData = media) => {
    const data = { id: crypto.randomUUID(), text, type, media: mediaData, time: 'just now', likes: 0, comments: 0 };
    savedPosts.unshift(data);
    persistPosts();
    addPost(data);
    document.querySelector('#postText').value = '';
    document.querySelector('#mediaUrl').value = '';
    document.querySelector('#mediaFile').value = '';
    modal.classList.remove('open');
    showToast('Your upload is live and saved on this device.');
  };
  if (!file) return savePost();
  const reader = new FileReader();
  reader.onload = () => savePost(reader.result);
  reader.onerror = () => showToast('Could not read that file.');
  reader.readAsDataURL(file);
});

function bindPostActions(scope = document, postId = '') {
  scope.querySelectorAll('.like-button').forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => {
      const count = button.querySelector('b');
      const liked = button.classList.toggle('liked');
      count.textContent = Number(count.textContent) + (liked ? 1 : -1);
      button.querySelector('span').textContent = liked ? '♥' : '♡';
      const post = savedPosts.find((item) => item.id === postId);
      if (post) { post.likes = Number(count.textContent); persistPosts(); }
    });
  });
  scope.querySelectorAll('.save-button').forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => {
      button.classList.toggle('saved');
      savedState[`saved-${postId}`] = button.classList.contains('saved');
      persistState();
      showToast(button.classList.contains('saved') ? 'Saved to your collection.' : 'Removed from saved.');
    });
  });
  scope.querySelectorAll('.comment-button').forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = 'true';
    button.addEventListener('click', () => {
      const comment = window.prompt('Write a comment');
      if (!comment?.trim()) return;
      const post = savedPosts.find((item) => item.id === postId);
      if (post) { post.comments = (post.comments || 0) + 1; persistPosts(); button.querySelector('b').textContent = post.comments; }
      showToast('Comment added.');
    });
  });
  scope.querySelectorAll('.share-button').forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = 'true';
    button.addEventListener('click', async () => {
      const text = button.closest('.post').querySelector('.post-copy').textContent;
      try { await navigator.clipboard.writeText(text); } catch { }
      showToast('Post text copied.');
    });
  });
}
bindPostActions();

document.querySelectorAll('.follow-button').forEach((button) => button.addEventListener('click', () => {
  button.classList.toggle('following');
  button.textContent = button.classList.contains('following') ? 'Following' : 'Follow';
  showToast(button.classList.contains('following') ? 'You are now following them.' : 'Unfollowed.');
}));
document.querySelector('.mini-profile').addEventListener('click', () => openAuth(localStorage.getItem('aikya-auth') ? 'user' : 'guest'));

let activeSearchCategory = 'all';
let searchRequestId = 0;
let searchDebounce;

function createSearchSection(container, title) {
  const section = document.createElement('section');
  section.className = 'search-result-section';
  const heading = document.createElement('h2');
  heading.textContent = title;
  const items = document.createElement('div');
  items.className = 'search-result-list';
  section.append(heading, items);
  container.append(section);
  return items;
}

function addSearchLink(container, href, title, detail) {
  const link = document.createElement('a');
  link.className = 'search-result-card search-link-card';
  link.href = href;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  const heading = document.createElement('strong');
  heading.textContent = title;
  const description = document.createElement('span');
  description.textContent = detail;
  link.append(heading, description);
  container.append(link);
}

function addSearchMessage(container, message) {
  const status = document.createElement('p');
  status.className = 'search-status';
  status.textContent = message;
  container.append(status);
}

function renderPeopleSearch(container, query) {
  const people = Object.values(getUsers()).map((user) => ({
    name: user.name || user.username || 'AiKya user',
    username: user.username || '',
    identity: user.identity || '',
    id: user.uid || '',
  }));
  document.querySelectorAll('.person, .post-author').forEach((element) => {
    const parent = element.closest('.person, .post-author');
    const name = parent.querySelector('strong')?.textContent.trim() || '';
    const username = parent.querySelector('small')?.textContent.trim().replace(/^@/, '') || parent.querySelector('span')?.textContent.match(/@([\w.-]+)/)?.[1] || '';
    if (name && !people.some((person) => person.name === name && person.username === username)) people.push({ name, username, identity: '', id: '' });
  });
  const matches = people.filter((person) => `${person.name} ${person.username} ${person.identity} ${person.id}`.toLowerCase().includes(query));
  if (!matches.length) return addSearchMessage(container, 'No matching people or IDs.');
  matches.slice(0, 20).forEach((person) => {
    const card = document.createElement('article');
    card.className = 'search-result-card';
    const heading = document.createElement('strong');
    heading.textContent = person.name;
    const detail = document.createElement('span');
    detail.textContent = [person.username && `@${person.username}`, person.identity, person.id].filter(Boolean).join(' · ') || 'AiKya profile';
    card.append(heading, detail);
    container.append(card);
  });
}

function renderPostSearch(container, query) {
  const posts = [...document.querySelectorAll('#feed > .post:not(.media-library-post)')].filter((post) => {
    const text = `${post.dataset.search || ''} ${post.textContent}`.toLowerCase();
    return text.includes(query);
  });
  if (!posts.length) return addSearchMessage(container, 'No matching AiKya posts.');
  posts.slice(0, 12).forEach((post) => {
    const card = document.createElement('article');
    card.className = 'search-result-card';
    const heading = document.createElement('strong');
    heading.textContent = post.querySelector('.post-author strong')?.textContent.trim() || 'AiKya post';
    const detail = document.createElement('span');
    detail.textContent = post.querySelector('.post-copy')?.textContent.trim() || post.dataset.search || '';
    card.append(heading, detail);
    container.append(card);
  });
}

function renderSongResults(container, tracks) {
  if (!tracks.length) return addSearchMessage(container, 'No matching songs found.');
  tracks.forEach((track) => {
    const card = document.createElement('article');
    card.className = 'search-result-card song-result-card';
    if (track.artworkUrl100) {
      const artwork = document.createElement('img');
      artwork.src = track.artworkUrl100;
      artwork.alt = '';
      artwork.loading = 'lazy';
      card.append(artwork);
    }
    const details = document.createElement('div');
    details.className = 'song-result-details';
    const heading = document.createElement('strong');
    heading.textContent = track.trackName || 'Unknown song';
    const artist = document.createElement('span');
    artist.textContent = track.artistName || 'Unknown artist';
    details.append(heading, artist);
    if (track.previewUrl) {
      const audio = document.createElement('audio');
      audio.controls = true;
      audio.preload = 'none';
      audio.src = track.previewUrl;
      audio.setAttribute('aria-label', `Preview ${track.trackName || 'song'}`);
      details.append(audio);
    }
    if (track.trackViewUrl) {
      const store = document.createElement('a');
      store.href = track.trackViewUrl;
      store.target = '_blank';
      store.rel = 'noopener noreferrer';
      store.textContent = 'Open in Apple Music';
      details.append(store);
    }
    card.append(details);
    container.append(card);
  });
}

function renderSearchHub() {
  document.querySelector('.search-hub')?.remove();
  document.querySelectorAll('.post').forEach((post) => post.classList.add('hidden'));
  const categories = [['all', 'All'], ['people', 'People / IDs'], ['songs', 'Songs'], ['videos', 'Videos'], ['movies', 'Movies / TV']];
  feed.insertAdjacentHTML('afterbegin', `<section class="search-hub" aria-label="Search"><div class="search-category-tabs" role="tablist" aria-label="Search category">${categories.map(([value, label]) => `<button class="search-category ${activeSearchCategory === value ? 'active' : ''}" type="button" role="tab" aria-selected="${activeSearchCategory === value}" data-search-category="${value}">${label}</button>`).join('')}</div><div class="search-results" aria-live="polite"></div></section>`);
  const hub = feed.querySelector('.search-hub');
  hub.querySelectorAll('.search-category').forEach((button) => button.addEventListener('click', () => {
    activeSearchCategory = button.dataset.searchCategory;
    hub.querySelectorAll('.search-category').forEach((tab) => {
      const selected = tab === button;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
    });
    runSearch(document.querySelector('#searchInput').value);
  }));
  runSearch(document.querySelector('#searchInput').value);
}

async function runSearch(rawQuery) {
  const query = String(rawQuery || '').trim().toLowerCase();
  const results = document.querySelector('.search-hub .search-results');
  if (!results) return;
  const requestId = ++searchRequestId;
  results.replaceChildren();
  if (!query) return;

  if (activeSearchCategory === 'all' || activeSearchCategory === 'people') {
    const people = createSearchSection(results, 'People / IDs');
    renderPeopleSearch(people, query);
  }
  if (activeSearchCategory === 'all') {
    const posts = createSearchSection(results, 'AiKya posts');
    renderPostSearch(posts, query);
  }
  if (activeSearchCategory === 'all' || activeSearchCategory === 'videos') {
    const videos = createSearchSection(results, 'Videos');
    addSearchLink(videos, `https://www.youtube.com/results?search_query=${encodeURIComponent(rawQuery.trim())}`, `Search YouTube for “${rawQuery.trim()}”`, 'Open video results on YouTube');
  }
  if (activeSearchCategory === 'all' || activeSearchCategory === 'songs') {
    const songs = createSearchSection(results, 'Songs');
    addSearchMessage(songs, 'Searching songs...');
    fetch(`https://itunes.apple.com/search?${new URLSearchParams({ term: rawQuery.trim(), entity: 'song', limit: '8' })}`)
      .then((response) => {
        if (!response.ok) throw new Error('Song search request failed');
        return response.json();
      })
      .then((data) => {
        if (requestId !== searchRequestId || !songs.isConnected) return;
        songs.replaceChildren();
        renderSongResults(songs, data.results || []);
      })
      .catch(() => {
        if (requestId === searchRequestId && songs.isConnected) addSearchMessage(songs, 'Song search is unavailable right now.');
      });
  }
  if ((activeSearchCategory === 'all' || activeSearchCategory === 'movies') && tmdbIsConfigured()) {
    const titles = createSearchSection(results, 'Movies / TV');
    addSearchMessage(titles, 'Searching titles...');
    fetchTmdb('/search/multi', { query: rawQuery.trim(), page: '1' })
      .then((data) => {
        if (requestId !== searchRequestId || !titles.isConnected) return;
        titles.replaceChildren();
        const items = (data.results || []).filter((item) => ['movie', 'tv'].includes(item.media_type));
        if (!items.length) return addSearchMessage(titles, 'No matching movies or shows.');
        items.slice(0, 8).forEach((item) => titles.append(createMovieCard(item, item.media_type)));
      })
      .catch(() => {
        if (requestId === searchRequestId && titles.isConnected) addSearchMessage(titles, 'Movie search is unavailable right now.');
      });
  } else if (activeSearchCategory === 'movies' && !tmdbIsConfigured()) {
    const titles = createSearchSection(results, 'Movies / TV');
    addSearchMessage(titles, 'Add a TMDB API key in firebase-config.js to search titles.');
  }
}

document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.remove('active'));
  button.classList.add('active');
  const view = button.dataset.view;
  document.body.classList.toggle('movies-view', view === 'movies');
  const titles = { home: ['Good morning, Sohail', 'Here is what is shaping your world today.'], discover: ['Search', 'People, songs, videos and more.'], clips: ['Clips made for you', 'A quick scroll through the best of AiKya.'], reels: ['Reels', 'Short vertical videos from your AiKya community.'], videos: ['Videos', 'Longer videos, tutorials and watch parties.'], movies: ['Movies', 'Full-length stories and featured films.'], tweets: ['Tweets', 'Short thoughts, updates and conversations.'], messages: ['Your conversations', 'Keep the good ideas moving.'], saved: ['Your saved world', 'Everything you wanted to come back to.'], settings: ['Make AiKya yours', 'Tune your experience.'] };
  document.querySelector('#viewTitle').textContent = titles[view][0] + '.';
  document.querySelector('#viewSubtitle').textContent = titles[view][1];
  document.body.classList.toggle('search-view', view === 'discover');
  if (view !== 'discover') document.querySelector('.search-hub')?.remove();
  if (view === 'settings') {
    openAuth(localStorage.getItem('aikya-auth') ? 'user' : 'guest');
    return;
  }
  if (view !== 'movies') {
    document.querySelector('.movie-catalog')?.remove();
    document.querySelectorAll('.post').forEach((post) => post.classList.remove('hidden'));
  }
  if (!['clips', 'reels', 'videos'].includes(view)) {
    document.querySelectorAll('.media-library-post, .media-empty').forEach((item) => item.remove());
  }
  if (view === 'home') {
    document.querySelectorAll('.post').forEach((post) => post.classList.remove('hidden'));
  }
  if (['clips', 'reels', 'videos'].includes(view) && !isSignedIn()) {
    openAuth('guest');
    showToast('Log in to watch videos and movies.');
    return;
  }
  if (view === 'movies') {
    renderMovieCatalog('movie');
  } else if (view === 'discover') {
    activeSearchCategory = 'all';
    renderSearchHub();
    document.querySelector('#searchInput').focus();
  } else if (view === 'videos' || view === 'clips' || view === 'reels') {
    renderMediaLibrary('videos');
  }
  if (view !== 'home') showToast(`${button.querySelector('span:last-of-type')?.textContent || view} view selected`);
}));

const mobileMoreToggle = document.querySelector('#mobileMoreToggle');
const mobileMoreMenu = document.querySelector('#mobileMoreMenu');
mobileMoreToggle.addEventListener('click', () => {
  const isOpen = mobileMoreMenu.classList.toggle('open');
  mobileMoreToggle.setAttribute('aria-expanded', String(isOpen));
});
mobileMoreMenu.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => {
  mobileMoreMenu.classList.remove('open');
  mobileMoreToggle.setAttribute('aria-expanded', 'false');
}));

document.querySelectorAll('.composer-tools > button:not(.publish-button)').forEach((button) => button.addEventListener('click', () => {
  const label = button.textContent.trim();
  if (label.includes('Photo')) { document.querySelector('#postType').value = 'image'; document.querySelector('#mediaUrl').focus(); showToast('Add a photo URL.'); }
  else if (label.includes('Clip')) { document.querySelector('#postType').value = 'video'; document.querySelector('#mediaUrl').focus(); showToast('Add a video URL.'); }
  else { document.querySelector('#postText').value += (document.querySelector('#postText').value ? ' ' : '') + 'Feeling grateful'; }
}));

document.querySelectorAll('.switch').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.switch').forEach((item) => item.classList.remove('active'));
  button.classList.add('active');
  showToast(button.textContent + ' feed loaded');
}));

document.querySelector('#searchInput').addEventListener('input', (event) => {
  if (document.body.classList.contains('search-view')) {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => runSearch(event.target.value), 250);
    return;
  }
  const query = event.target.value.trim().toLowerCase();
  if (query && isSignedIn()) renderMediaLibrary('all', query);
  if (!query) document.querySelectorAll('.media-library-post, .media-empty').forEach((item) => item.remove());
  document.querySelectorAll('.post').forEach((post) => post.classList.toggle('hidden', query && !post.dataset.search.includes(query)));
  if (query && !isSignedIn()) {
    openAuth('guest');
    showToast('Log in to search and watch videos or movies.');
  }
});

function openOverlay(title, body, actions = '') {
  const overlay = document.createElement('div');
  overlay.className = 'feature-overlay';
  overlay.innerHTML = `<div class="feature-backdrop"></div><div class="feature-panel"><button class="close-button feature-close">×</button><p class="eyebrow">AiKya</p><h2>${title}</h2><div class="feature-body">${body}</div>${actions}</div>`;
  document.body.append(overlay);
  overlay.querySelector('.feature-close').addEventListener('click', () => overlay.remove());
  overlay.querySelector('.feature-backdrop').addEventListener('click', () => overlay.remove());
  return overlay;
}

document.querySelectorAll('.story').forEach((story) => story.addEventListener('click', () => {
  const name = story.querySelector('span:last-child').textContent;
  if (name === 'Your story') {
    const existing = JSON.parse(localStorage.getItem('aikya-story') || 'null');
    const overlay = openOverlay('Your story', `<div class="story-owner-card"><div class="story-large-avatar">S</div><div><b>${existing ? 'Your story is live' : 'Share a quick moment'}</b><small>${existing ? 'Visible for 24 hours' : 'Add a photo, video or note'}</small></div></div><textarea id="storyText" placeholder="What is happening?"></textarea><input id="storyMedia" type="url" placeholder="Optional photo or video URL"><div class="story-options"><button id="storyCamera">▣ Camera</button><button id="storyGallery">▧ Gallery</button><button id="storyDraw">✎ Draw</button><button id="storySticker">☺ Sticker</button></div><button class="auth-submit" id="publishStory">Share story</button><div class="story-management"><button id="storyViewers">Viewers</button><button id="storyArchive">Archive</button><button id="storyDelete">Delete</button></div>`);
    overlay.querySelector('#publishStory').addEventListener('click', () => { const text = overlay.querySelector('#storyText').value.trim(); if (!text) return showToast('Write something for your story.'); localStorage.setItem('aikya-story', JSON.stringify({ text, media: overlay.querySelector('#storyMedia').value.trim(), time: Date.now() })); overlay.remove(); showToast('Your story is live for 24 hours.'); });
    overlay.querySelector('#storyCamera').addEventListener('click', () => showToast('Camera ready. Use the message camera to capture media.'));
    overlay.querySelector('#storyGallery').addEventListener('click', () => overlay.querySelector('#storyMedia').focus());
    overlay.querySelector('#storyDraw').addEventListener('click', () => { overlay.querySelector('#storyText').value += ' [Drawing]'; });
    overlay.querySelector('#storySticker').addEventListener('click', () => { overlay.querySelector('#storyText').value += ' 😊'; });
    overlay.querySelector('#storyViewers').addEventListener('click', () => showToast('Viewers: Maya, Arjun and 8 others.'));
    overlay.querySelector('#storyArchive').addEventListener('click', () => showToast('Story saved to archive.'));
    overlay.querySelector('#storyDelete').addEventListener('click', () => { localStorage.removeItem('aikya-story'); overlay.remove(); showToast('Story deleted.'); });
    return;
  }
  const viewer = openOverlay(`${name}'s story`, `<div class="story-viewer"><div class="story-progress"><i></i></div><div class="story-viewer-top"><button id="storyPause">Ⅱ</button><button id="storyMute">🔊</button></div><div class="story-large-avatar">${name.charAt(0)}</div><p>${name} shared a new moment. Stories disappear after 24 hours.</p><div class="story-reactions"><button>❤️</button><button>😂</button><button>🔥</button><button>👏</button></div><div class="story-reply-box"><input id="storyReplyText" placeholder="Send message"><button class="story-send">➤</button></div><div class="story-view-actions"><button class="story-share">↗ Share</button><button class="story-follow">Follow</button></div></div>`);
  let paused = false;
  const progress = viewer.querySelector('.story-progress i');
  progress.style.animation = 'story-progress 7s linear forwards';
  viewer.querySelector('#storyPause').addEventListener('click', (event) => { paused = !paused; progress.style.animationPlayState = paused ? 'paused' : 'running'; event.target.textContent = paused ? '▶' : 'Ⅱ'; });
  viewer.querySelector('#storyMute').addEventListener('click', (event) => { event.target.textContent = event.target.textContent === '🔊' ? '🔇' : '🔊'; });
  viewer.querySelectorAll('.story-reactions button').forEach((reaction) => reaction.addEventListener('click', () => showToast(`Reaction ${reaction.textContent} sent to ${name}.`)));
  viewer.querySelector('.story-send').addEventListener('click', () => { const reply = viewer.querySelector('#storyReplyText').value.trim(); if (reply) { viewer.remove(); showToast(`Reply sent to ${name}.`); } });
  viewer.querySelector('.story-share').addEventListener('click', () => { try { navigator.clipboard.writeText(`${name}'s story on AiKya`); } catch {} showToast('Story link copied.'); });
  viewer.querySelector('.story-follow').addEventListener('click', (event) => { event.target.textContent = event.target.textContent === 'Follow' ? 'Following' : 'Follow'; });
}));

document.querySelector('.icon-button').addEventListener('click', () => {
  document.querySelector('.notification-dot').style.display = 'none';
  openOverlay('Notifications', '<div class="notification-item"><b>Maya Chen</b> liked your interests.</div><div class="notification-item"><b>Jules Park</b> started following you.</div><div class="notification-item"><b>AiKya</b> has new clips for you.</div>');
});

document.querySelectorAll('.play-button').forEach((button) => button.addEventListener('click', () => {
  const playing = button.dataset.playing === 'true';
  button.dataset.playing = String(!playing);
  button.textContent = playing ? '▶' : '❚❚';
  button.closest('.music-card').classList.toggle('playing', !playing);
  showToast(playing ? 'Playback paused.' : 'Playing Between Stations.');
}));

document.querySelectorAll('.trend').forEach((trend) => trend.addEventListener('click', () => {
  const query = trend.querySelector('strong').textContent;
  document.querySelector('#searchInput').value = query;
  document.querySelectorAll('.post').forEach((post) => post.classList.toggle('hidden', !post.dataset.search.includes(query.replace('#', '').toLowerCase())));
  showToast(`Showing posts for ${query}.`);
}));
document.querySelector('.trend-card .plain-button').addEventListener('click', () => { document.querySelector('#searchInput').focus(); showToast('Search a topic to explore AiKya.'); });
document.querySelector('.people-card .plain-button').addEventListener('click', () => showToast('People suggestions refreshed.'));

document.querySelectorAll('.post-menu').forEach((button) => button.addEventListener('click', () => {
  const action = window.prompt('Post options: type report, hide, or cancel');
  if (action === 'hide') { button.closest('.post').classList.add('hidden'); showToast('Post hidden from your feed.'); }
  if (action === 'report') showToast('Thanks. The post was sent for review.');
}));

document.querySelectorAll('.nav-item').forEach((button) => button.addEventListener('click', () => {
  const view = button.dataset.view;
  if (view === 'messages') {
    const conversations = [{ id: 'maya', name: 'Maya Chen', handle: '@mayamakes', avatar: 'M', color: 'avatar-maya', preview: 'Want to collaborate on a new post?' }, { id: 'jules', name: 'Jules Park', handle: '@julesinmotion', avatar: 'J', color: 'avatar-person', preview: 'Welcome to AiKya.' }, { id: 'kiara', name: 'Kiara Mehta', handle: '@kiaramehta', avatar: 'K', color: 'avatar-person two', preview: 'That reel was beautiful.' }];
    const messages = JSON.parse(localStorage.getItem('aikya-messages') || '{}');
    const overlay = openOverlay('Messages', `<div class="dm-layout"><aside class="dm-sidebar"><div class="dm-heading"><b>Chats</b><button class="dm-compose" title="New message">✎</button></div><input class="dm-search" placeholder="Search messages"><div class="dm-conversations">${conversations.map((person) => `<button class="dm-conversation active" data-chat="${person.id}"><div class="avatar ${person.color}">${person.avatar}</div><span><b>${person.name}</b><small>${person.preview}</small></span><i></i></button>`).join('')}</div></aside><section class="dm-chat"><header class="dm-chat-header"><div class="avatar avatar-maya" id="dmAvatar">M</div><div><b id="dmName">Maya Chen</b><small id="dmHandle">@mayamakes</small></div><div class="dm-call-actions"><button id="dmAudioCall" title="Audio call">☎</button><button id="dmVideoCall" title="Video call">▣</button><button class="dm-info">ⓘ</button></div></header><div class="dm-thread" id="dmThread"></div><div class="dm-plus-menu" id="dmPlusMenu"><button data-dm-tool="gallery">▧ Gallery</button><button data-dm-tool="camera">▣ Photo / video</button><button data-dm-tool="gif">GIF</button><button data-dm-tool="sticker">☺ Sticker</button><button data-dm-tool="avatar">◉ Avatar</button><button data-dm-tool="draw">✎ Draw</button><button data-dm-tool="ai">✦ AI image</button><button data-dm-tool="reply">↺ Saved replies</button><button data-dm-tool="location">⌖ Location</button><button data-dm-tool="saved">▱ Saved media</button></div><div class="dm-composer"><button class="dm-attach" id="dmPlus" title="More message options">＋</button><button class="dm-camera" id="dmCamera" title="Camera">▣</button><input id="messageText" placeholder="Message..." autocomplete="off"><button class="dm-voice" id="dmVoice" title="Record voice">●</button><button class="dm-send" id="sendMessage">Send</button><input id="dmFile" type="file" accept="image/*,video/*" capture="environment" hidden></div></section></div>`);
    const thread = overlay.querySelector('#dmThread');
    let selected = conversations[0];
    function renderThread() {
      const items = messages[selected.id] || [{ from: 'them', text: selected.preview, time: '2:41 PM' }];
      const bubble = (item) => {
        if (item.kind === 'photo') return `<img class="dm-media" src="${item.text.replace('Photo: ', '')}" alt="Shared photo">`;
        if (item.kind === 'video') return `<video class="dm-media" src="${item.text.replace('Video: ', '')}" controls></video>`;
        if (item.kind === 'voice') return `<audio class="dm-audio" src="${item.text.replace('Voice message recorded: ', '')}" controls></audio>`;
        return item.text;
      };
      thread.innerHTML = `<div class="dm-date">Today · ${selected.name} is active</div>${items.map((item, index) => `<div class="dm-bubble-row ${item.from === 'me' ? 'mine' : ''}" data-message-index="${index}"><div class="dm-bubble">${bubble(item)}${item.viewLimit ? `<small class="view-limit">${item.viewLimit === 'unlimited' ? 'Unlimited views' : `${item.viewLimit === 'twice' ? '2 views' : '1 view once'}`}</small>` : ''}<small>${item.time || 'now'} · ${item.from === 'me' ? 'Seen' : ''}</small><button class="bubble-more" title="Message options">•••</button></div></div>`).join('')}`;
      thread.scrollTop = thread.scrollHeight;
      overlay.querySelector('#dmName').textContent = selected.name;
      overlay.querySelector('#dmHandle').textContent = selected.handle;
      overlay.querySelector('#dmAvatar').textContent = selected.avatar;
      overlay.querySelector('#dmAvatar').className = `avatar ${selected.color}`;
      thread.querySelectorAll('.bubble-more').forEach((more) => more.addEventListener('click', () => {
        const row = more.closest('.dm-bubble-row');
        const index = Number(row.dataset.messageIndex);
        const action = window.prompt('Message options: type react, reply, delete, or cancel');
        if (action === 'react') { messages[selected.id][index].reaction = '❤️'; localStorage.setItem('aikya-messages', JSON.stringify(messages)); renderThread(); }
        if (action === 'reply') { const reply = window.prompt('Reply to this message'); if (reply) addDmMessage(`Reply: ${reply}`); }
        if (action === 'delete' && messages[selected.id]?.[index]) { messages[selected.id].splice(index, 1); localStorage.setItem('aikya-messages', JSON.stringify(messages)); renderThread(); }
      }));
      thread.querySelectorAll('.dm-bubble').forEach((bubbleElement, index) => { const item = items[index]; if (item?.reaction) { const reaction = document.createElement('span'); reaction.className = 'message-reaction'; reaction.textContent = item.reaction; bubbleElement.append(reaction); } });
    }
    function addDmMessage(text, kind = 'text', viewLimit = 'unlimited') {
      messages[selected.id] = [...(messages[selected.id] || []), { from: 'me', text, kind, viewLimit, time: new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) }];
      localStorage.setItem('aikya-messages', JSON.stringify(messages));
      renderThread();
    }
    function sendMessage() {
      const input = overlay.querySelector('#messageText');
      const text = input.value.trim();
      if (!text) return;
      addDmMessage(text, 'text', overlay.querySelector('#dmViewLimit')?.value || 'unlimited');
      input.value = '';
    }
    overlay.querySelectorAll('.dm-conversation').forEach((chatButton) => chatButton.addEventListener('click', () => { overlay.querySelectorAll('.dm-conversation').forEach((item) => item.classList.remove('active')); chatButton.classList.add('active'); selected = conversations.find((person) => person.id === chatButton.dataset.chat); renderThread(); }));
    overlay.querySelector('#sendMessage').addEventListener('click', sendMessage);
    overlay.querySelector('#messageText').addEventListener('keydown', (event) => { if (event.key === 'Enter') sendMessage(); });
    overlay.querySelector('.dm-search').addEventListener('input', (event) => { const query = event.target.value.toLowerCase(); overlay.querySelectorAll('.dm-conversation').forEach((item) => item.classList.toggle('hidden', !item.textContent.toLowerCase().includes(query))); });
    overlay.querySelector('.dm-attach').addEventListener('click', () => showToast('Attachment picker is ready for the next message.'));
    overlay.querySelector('.dm-compose').addEventListener('click', () => overlay.querySelector('.dm-search').focus());
    overlay.querySelector('#dmPlus').addEventListener('click', () => { overlay.querySelector('#dmPlusMenu').classList.toggle('open'); if (!overlay.querySelector('#dmViewLimit')) { const label = document.createElement('label'); label.className = 'dm-once'; label.innerHTML = 'Camera views <select id="dmViewLimit"><option value="once">1 view once</option><option value="twice">2 views</option><option value="unlimited" selected>Unlimited views</option></select>'; overlay.querySelector('.dm-composer').prepend(label); } });
    overlay.querySelectorAll('[data-dm-tool]').forEach((tool) => tool.addEventListener('click', () => {
      const action = tool.dataset.dmTool;
      overlay.querySelector('#dmPlusMenu').classList.remove('open');
      if (action === 'gallery' || action === 'camera') { overlay.querySelector('#dmFile').click(); return; }
      if (action === 'gif') return addDmMessage('GIF: ✨🎬', 'gif');
      if (action === 'sticker') return addDmMessage('Sticker: 😊💚', 'sticker');
      if (action === 'avatar') return addDmMessage('Avatar: 🧑‍🚀', 'avatar');
      if (action === 'reply') { const reply = window.prompt('Saved reply', 'Thanks for your message!'); if (reply) addDmMessage(reply); return; }
      if (action === 'location') return addDmMessage('Location: https://maps.google.com/?q=28.6139,77.2090', 'location');
      if (action === 'saved') { const saved = savedPosts.filter((post) => savedState[`saved-${post.id}`]); return addDmMessage(saved.length ? `Saved media: ${saved.map((post) => post.text).join(' | ')}` : 'Saved media is empty.', 'saved'); }
      if (action === 'ai') return addDmMessage('AI image generated: https://images.unsplash.com/photo-1519608487953-e999c86e7455?w=800', 'ai');
      if (action === 'draw') { const draw = window.prompt('Draw mode: describe your drawing'); if (draw) addDmMessage(`Drawing: ${draw}`, 'draw'); }
    }));
    overlay.querySelector('#dmFile').addEventListener('change', () => { const file = overlay.querySelector('#dmFile').files[0]; if (!file) return; const reader = new FileReader(); reader.onload = () => addDmMessage(`${file.type.startsWith('video') ? 'Video' : 'Photo'}: ${reader.result}`, file.type.startsWith('video') ? 'video' : 'photo', overlay.querySelector('#dmViewLimit')?.value || 'unlimited'); reader.readAsDataURL(file); });
    overlay.querySelector('#dmCamera').addEventListener('click', () => overlay.querySelector('#dmFile').click());
    async function startCall(videoEnabled) {
      if (!navigator.mediaDevices?.getUserMedia) return showToast('Calls need browser camera and microphone permission.');
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true, video: videoEnabled });
        const call = openOverlay(videoEnabled ? `Video call with ${selected.name}` : `Audio call with ${selected.name}`, `<div class="call-screen"><div class="call-avatar avatar ${selected.color}">${selected.avatar}</div>${videoEnabled ? '<video id="localCallVideo" class="call-video" autoplay muted playsinline></video>' : '<p class="call-status">Microphone connected</p>'}<p class="call-status">Calling ${selected.name}...</p><button class="end-call" id="endCall">End call</button></div>`);
        if (videoEnabled) call.querySelector('#localCallVideo').srcObject = stream;
        call.querySelector('#endCall').addEventListener('click', () => { stream.getTracks().forEach((track) => track.stop()); call.remove(); showToast('Call ended.'); });
      } catch { showToast('Camera or microphone permission was denied.'); }
    }
    overlay.querySelector('#dmAudioCall').addEventListener('click', () => startCall(false));
    overlay.querySelector('#dmVideoCall').addEventListener('click', () => startCall(true));
    overlay.querySelector('#dmVoice').addEventListener('click', async () => { if (!navigator.mediaDevices?.getUserMedia) return showToast('Voice recording needs a secure browser permission.'); try { const stream = await navigator.mediaDevices.getUserMedia({ audio: true }); const recorder = new MediaRecorder(stream); const chunks = []; recorder.ondataavailable = (event) => chunks.push(event.data); recorder.onstop = () => { stream.getTracks().forEach((track) => track.stop()); const audioUrl = URL.createObjectURL(new Blob(chunks, { type: 'audio/webm' })); addDmMessage(`Voice message recorded: ${audioUrl}`, 'voice'); }; recorder.start(); overlay.querySelector('#dmVoice').textContent = '■'; setTimeout(() => recorder.stop(), 3000); } catch { showToast('Microphone permission was denied.'); } });
    renderThread();
  }
  if (view === 'saved') {
    const saved = document.querySelectorAll('.save-button.saved').length;
    showToast(saved ? `${saved} saved post${saved > 1 ? 's' : ''} in your collection.` : 'Save a post to see it here.');
  }
  if (view === 'clips' || view === 'reels' || view === 'videos' || view === 'movies' || view === 'tweets') { const match = view === 'reels' ? ['reel'] : view === 'videos' || view === 'clips' ? ['video', 'music'] : view === 'movies' ? ['movie'] : ['tweet', 'text']; document.querySelectorAll('.post').forEach((post) => { const type = post.dataset.type || (post.querySelector('video') ? 'video' : post.querySelector('.music-card') ? 'music' : 'text'); post.classList.toggle('hidden', !match.includes(type)); }); showToast(`${view.charAt(0).toUpperCase() + view.slice(1)} section loaded.`); }
  if (view === 'discover') { document.querySelectorAll('.post').forEach((post) => post.classList.add('hidden')); showToast('Search ready.'); }
}));
