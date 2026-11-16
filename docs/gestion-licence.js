'use strict';

const $ = selector => document.querySelector(selector);
const REPO = 'zwalid2-ux/gestion-stock-licences';
const API = `https://api.github.com/repos/${REPO}`;
const BRANCH = 'main';
const DATABASE = 'admin/activations.v1.enc.json';
const KEY_INFO = 'STOKY GitHub licence store v1';
// Accès par identifiant et mot de passe : le jeton et la clé de signature sont chiffrés avec une clé dérivée du mot
// de passe (PBKDF2) puis publiés ; sans le mot de passe, le fichier publié ne révèle ni l'un ni l'autre.
const ACCESS_INFO = 'STOKY licence access v1:';
const ACCESS_ITERATIONS = 600000;
const ACCESS_PASSWORD_LENGTH = 12;
const CACHE_KEY = 'stoky-licence-snapshot-v1';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const FEATURES = [
  ['photos', 'Photos en ligne'], ['docclient', 'Document Client et historique'],
  ['portail', 'Portail Client'], ['depots', 'Gestion des dépôts'], ['arrivage', 'Arrivage'],
  ['listing', 'Listing'], ['autofacture', 'Auto Facture'], ['livraison', 'Livraison'],
  ['pieces', 'Ctrl+C = Car Parts Search'], ['employes', 'Gestion des employés'],
  ['tva', 'État TVA'], ['cheque', 'Imprimer chèque'],
  ['github', 'Sauvegarde GitHub et restauration'], ['zerotier', 'Accès privé avec ZeroTier'],
  ['chat', 'Chat local'], ['ia', 'IA Assistant'], ['telegram', 'Notification Telegram'],
];
const DOMAINS = { pieces: 'Pièces de rechange', camera: 'Caméra de surveillance',
  superette: 'Supérette', informatique: 'Informatique' };
const labels = { Pending: 'En attente', Approved: 'Accordée', Expired: 'Expirée',
  Revoked: 'Révoquée', Rejected: 'Refusée', ReviewRequired: 'À vérifier',
  Active: 'Active confirmée', ExternalLicensed: 'Licence externe signée',
  Unknown: 'Pas encore signalée', Missing: 'Licence non reçue',
  Invalid: 'Signature / appareil invalide', OutOfDate: 'Ancienne version à synchroniser' };
const kindNames = { Permanent: 'Permanente', Trial15: 'Essai 15 jours',
  Trial30: 'Essai 30 jours', Trial: 'Licence temporaire' };

let items = [], selectedId = null, headSha = null, busy = false, loading = false;
let githubToken = '', signingKey = null, keyBytes = null, publicKey = null, pollTimer = null;
let ready = false, accessUser = '';

const base64 = bytes => {
  let value = '';
  for (let offset = 0; offset < bytes.length; offset += 32768)
    value += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
  return btoa(value);
};
const unbase64 = value => Uint8Array.from(atob(value.replace(/\s/g, '')), c => c.charCodeAt(0));
const url64 = bytes => base64(bytes).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
const esc = value => {
  const element = document.createElement('div');
  element.textContent = value == null ? '' : String(value);
  return element.innerHTML;
};
const date = value => {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '-';
  const p = n => String(n).padStart(2, '0');
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}`;
};
const ago = value => {
  if (!value) return 'jamais';
  const days = Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 86400000));
  return days === 0 ? "aujourd'hui" : `il y a ${days} j`;
};
const featureLabel = code => FEATURES.find(feature => feature[0] === code)?.[1] || code;
const effectiveFeatures = record => record.grantedFeatures ?? record.requestedFeatures;
const featuresSummary = record => {
  const features = effectiveFeatures(record);
  return features == null ? 'toutes les options' :
    features.length ? `${features.length}/${FEATURES.length} options` : 'aucune option';
};
const normalizeMachine = value => (value || '').replace(/[-\s]/g, '').toUpperCase();
const TOKEN_HELP = "Ce jeton GitHub peut lire le dépôt des licences mais n'a pas le droit d'y écrire. " +
  'Créez un jeton à accès fin : « Repository access » → « Only select repositories » → gestion-stock-licences, ' +
  'puis « Repository permissions » → « Contents » → « Read and write ». ' +
  'Un jeton classique doit avoir la portée « public_repo ».';
function message(text, error = false) {
  for (const element of document.querySelectorAll('#message, dialog[open] .dialog-message')) {
    element.textContent = text;
    element.classList.toggle('error', error);
  }
}
function setBusy(value) {
  busy = value;
  for (const button of document.querySelectorAll('#details button, #requestBox button, #accessBox button'))
    button.disabled = value;
}
function progress(text) {
  if (!$('#login').classList.contains('hidden')) $('#loginStatus').textContent = text;
  else $('#serverState').textContent = text;
}
function clearCredentials() {
  githubToken = '';
  signingKey = null;
  publicKey = null;
  if (keyBytes) keyBytes.fill(0);
  keyBytes = null;
  headSha = null;
  ready = false;
  accessUser = '';
}

// Depuis certains réseaux, une tentative de connexion vers GitHub sur plusieurs reste sans réponse une vingtaine de
// secondes. Chaque requête a donc un délai court et jusqu'à trois essais ; pour une lecture, l'essai suivant part
// après quelques secondes sans attendre l'échec du précédent, et la première réponse gagne.
const RETRY_AFTER = 3000;
function request(url, options, timeout, { overlap = false, quiet = false } = {}) {
  return new Promise((resolve, reject) => {
    const controllers = [];
    let settled = false, started = 0, failures = 0;
    const start = () => {
      if (settled || started >= 3) return;
      if (++started > 1 && !quiet) progress(`GitHub ne répond pas, nouvel essai ${started}/3…`);
      const controller = new AbortController();
      controllers.push(controller);
      const limit = setTimeout(() => controller.abort(), timeout);
      (async () => {
        const response = await fetch(url, { ...options, cache: 'no-store', signal: controller.signal });
        const text = await response.text();
        let data = null;
        try { data = text ? JSON.parse(text) : null; } catch { data = null; }
        return { response, data };
      })().then(result => {
        clearTimeout(limit);
        if (settled) return;
        settled = true;
        for (const other of controllers) if (other !== controller) other.abort();
        resolve(result);
      }, error => {
        clearTimeout(limit);
        if (settled) return;
        if (++failures >= 3) {
          settled = true;
          const failure = new Error(error.name === 'AbortError'
            ? 'GitHub ne répond pas (délai dépassé). Vérifiez la connexion Internet, puis réessayez.'
            : 'GitHub est injoignable. Vérifiez la connexion Internet, puis réessayez.');
          failure.network = true;
          reject(failure);
        } else if (failures === started) start();
      });
      if (overlap) setTimeout(start, RETRY_AFTER);
    };
    start();
  });
}

async function github(method, path, body, accept = 'application/vnd.github+json', anonymous = false) {
  const { response, data } = await request(API + path, {
    method,
    headers: {
      Accept: accept,
      ...(anonymous ? {} : { Authorization: `Bearer ${githubToken}` }),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  }, method === 'GET' ? 9000 : 25000, { overlap: method === 'GET', quiet: anonymous });
  if (!response.ok) {
    const text = data?.message || response.statusText;
    const error = new Error(
      response.status === 403 && /not accessible by|must have (admin|push)|write access/i.test(text) ? TOKEN_HELP
        : response.status === 401 ? (accessUser
          ? 'Le jeton GitHub enregistré avec cet identifiant a expiré : ouvrez « Première connexion ou jeton expiré », ' +
            'connectez-vous avec un nouveau jeton et la clé, puis recréez la connexion par mot de passe (🔐).'
          : 'Jeton GitHub refusé ou expiré : créez-en un nouveau.')
          : `GitHub (${response.status}) : ${text}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

async function aesKey(salt) {
  const material = await crypto.subtle.importKey('raw', keyBytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(KEY_INFO) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function decrypt(envelope) {
  if (envelope.version !== 1 || typeof envelope.publicKey !== 'string' ||
      typeof envelope.salt !== 'string' || typeof envelope.nonce !== 'string' ||
      typeof envelope.ciphertext !== 'string')
    throw Error('Format de la base GitHub inconnu ou endommagé.');
  if (publicKey && publicKey !== envelope.publicKey)
    throw Error('La clé de signature de la base GitHub a changé ; aucune donnée ne sera remplacée.');
  const verificationKey = await crypto.subtle.importKey('spki', unbase64(envelope.publicKey),
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const challenge = encoder.encode(KEY_INFO);
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signingKey, challenge);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verificationKey, signature, challenge))
    throw Error("La clé privée choisie n'est pas celle des licences existantes.");
  const salt = unbase64(envelope.salt), nonce = unbase64(envelope.nonce);
  if (salt.length !== 16 || nonce.length !== 12)
    throw Error('Paramètres de chiffrement GitHub invalides.');
  const key = await aesKey(salt);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce },
    key, unbase64(envelope.ciphertext));
  publicKey = envelope.publicKey;
  return JSON.parse(decoder.decode(plaintext));
}
async function encrypt(records) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(salt);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce },
    key, encoder.encode(JSON.stringify(records)));
  return { version: 1, publicKey, salt: base64(salt), nonce: base64(nonce),
    ciphertext: base64(new Uint8Array(ciphertext)) };
}

function cachedEnvelope(head) {
  try {
    const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
    return cached?.head === head && cached.envelope?.version === 1 ? cached.envelope : null;
  } catch { return null; }
}
function rememberEnvelope(head, envelope) {
  // La base publiée est déjà chiffrée : la garder ici évite de retélécharger une version inchangée.
  try { localStorage.setItem(CACHE_KEY, JSON.stringify({ head, envelope })); } catch { }
}
// La base publiée est publique et chiffrée : la page la télécharge dès son ouverture, sans jeton, pendant la
// saisie de l'identifiant. La connexion n'a alors plus qu'à la déchiffrer.
let earlySnapshot = null, earlyAccess = null, warming = false;
async function warmUp() {
  if (warming || githubToken || (earlySnapshot && Date.now() - earlySnapshot.at < 60000)) return;
  warming = true;
  const state = $('#linkState');
  let slow = false;
  try {
    for (let round = 0; round < 6 && !githubToken; round++) {
      try {
        const head = (await github('GET', `/git/ref/heads/${BRANCH}`, undefined, undefined, true)).object.sha;
        const envelope = cachedEnvelope(head) || await github('GET',
          `/contents/${DATABASE}?ref=${encodeURIComponent(head)}`, undefined, 'application/vnd.github.raw+json', true);
        if (envelope?.version === 1) {
          rememberEnvelope(head, envelope);
          earlySnapshot = { head, envelope, at: Date.now() };
        }
        state.textContent = '● GitHub joignable';
        state.className = 'link-ok';
        return;
      } catch (error) {
        // Limite de requêtes anonymes ou autre refus : la connexion fera elle-même ses lectures.
        if (!error.network) { state.textContent = ''; return; }
        slow = true;
        state.textContent = '● GitHub répond mal depuis ce réseau : nouvelle tentative en cours…';
        state.className = 'link-slow';
      }
    }
    if (slow) state.textContent = '● GitHub répond mal depuis ce réseau : la connexion peut demander plusieurs essais.';
  } finally { warming = false; }
}
function prepareAccess() {
  const user = normalizeUser($('#loginUser').value);
  if (user && !githubToken && earlyAccess?.user !== user)
    earlyAccess = { user, file: fetchAccessFile(user, true).catch(() => null) };
}
async function readSnapshot() {
  const early = !ready && earlySnapshot && Date.now() - earlySnapshot.at < 120000 ? earlySnapshot : null;
  earlySnapshot = null;
  // Une version lue il y a moins de deux minutes suffit pour afficher : chaque enregistrement revérifie la branche.
  const head = early ? early.head : (await github('GET', `/git/ref/heads/${BRANCH}`)).object.sha;
  if (ready && head === headSha) return { head, records: items };
  let envelope = early?.envelope || cachedEnvelope(head);
  if (!envelope) {
    try {
      envelope = await github('GET', `/contents/${DATABASE}?ref=${encodeURIComponent(head)}`,
        undefined, 'application/vnd.github.raw+json');
    } catch (error) {
      if (error.status === 404)
        throw Error("Base GitHub absente : exportez d'abord la base du serveur avec --export-github. Aucune base vide ne sera créée.");
      throw error;
    }
    if (!envelope || typeof envelope !== 'object')
      throw Error('GitHub a renvoyé un format de base inattendu.');
  }
  const records = await decrypt(envelope);
  if (!Array.isArray(records) || records.some(record =>
    !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(record.id) ||
    !/^[0-9a-f]{16}$/i.test(normalizeMachine(record.machineCode)) ||
    typeof record.installationId !== 'string' || !record.installationId.length ||
    !Number.isInteger(record.revision) || record.revision < 0))
    throw Error('La base GitHub contient des installations invalides ; aucune modification ne sera faite.');
  rememberEnvelope(head, envelope);
  return { head, records };
}

const normalizeUser = value => (value || '').trim().toLowerCase();
async function accessPath(user) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(ACCESS_INFO + user)));
  return `access/${Array.from(hash.slice(0, 16), byte => byte.toString(16).padStart(2, '0')).join('')}.json`;
}
async function accessKey(user, password, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(`${user}\u0000${password}`),
    'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sealAccess(user, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await accessKey(user, password, salt, ACCESS_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: encoder.encode(ACCESS_INFO + user) }, key,
    encoder.encode(JSON.stringify({ token: githubToken, key: base64(keyBytes) })));
  return { version: 1, kdf: 'PBKDF2-SHA256', iterations: ACCESS_ITERATIONS, salt: base64(salt),
    nonce: base64(nonce), ciphertext: base64(new Uint8Array(ciphertext)) };
}
async function openAccessFile(file, user, password) {
  if (file?.version !== 1 || file.kdf !== 'PBKDF2-SHA256' || !Number.isInteger(file.iterations) ||
      file.iterations < 100000 || file.iterations > 10000000 || typeof file.salt !== 'string' ||
      typeof file.nonce !== 'string' || typeof file.ciphertext !== 'string')
    throw Error("Format de l'accès par mot de passe inconnu ou endommagé.");
  try {
    const key = await accessKey(user, password, unbase64(file.salt), file.iterations);
    const secret = JSON.parse(decoder.decode(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unbase64(file.nonce), additionalData: encoder.encode(ACCESS_INFO + user) },
      key, unbase64(file.ciphertext))));
    if (typeof secret.token !== 'string' || typeof secret.key !== 'string') throw Error();
    return secret;
  } catch { throw Error('Identifiant ou mot de passe incorrect.'); }
}
async function fetchAccessFile(user, quiet = false) {
  const path = await accessPath(user);
  let unreachable = 0, pending = 2;
  // En parallèle : le site de la page et l'API GitHub (à jour dès la création de l'accès) ; la première réponse valide gagne.
  const file = await new Promise(resolve => {
    for (const [url, headers] of [[`${path}?t=${Date.now()}`, {}],
      [`${API}/contents/docs/${path}?ref=${BRANCH}`, { Accept: 'application/vnd.github.raw+json' }]])
      request(url, { headers }, 9000, { overlap: true, quiet })
        .then(({ response, data }) => response.ok && data?.version === 1 ? data : null, () => { unreachable++; return null; })
        .then(found => { if (found) resolve(found); else if (--pending === 0) resolve(null); });
  });
  if (file) return file;
  throw Error(unreachable
    ? 'GitHub est injoignable. Vérifiez la connexion Internet, puis réessayez.'
    : 'Identifiant inconnu. Si la connexion par mot de passe n\'a pas encore été créée, ouvrez ' +
      '« Première connexion ou jeton expiré ».');
}

const writeCheck = () => github('POST', '/git/blobs',
  { content: base64(encoder.encode('STOKY write check')), encoding: 'base64' });
async function openSession(checkWriteFirst) {
  signingKey = await crypto.subtle.importKey('pkcs8', keyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  progress('Lecture des licences sur GitHub…');
  // Un objet Git non référencé vérifie le droit d'écriture réel du jeton. À la première connexion, il est attendu
  // avant d'ouvrir ; avec un accès par mot de passe (jeton déjà vérifié à sa création), il ne retarde pas l'affichage.
  const probe = writeCheck();
  probe.catch(() => { });
  const snapshot = await readSnapshot();
  if (checkWriteFirst) await probe;
  items = snapshot.records;
  headSha = snapshot.head;
  ready = true;
  for (const id of ['githubToken', 'signingKey', 'loginPassword']) $(`#${id}`).value = '';
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#headerActions').classList.remove('hidden');
  $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
  render();
  if (!accessUser)
    message('Astuce : le bouton 🔐 crée une connexion par identifiant et mot de passe, sans jeton ni fichier de clé.');
  if (!pollTimer) pollTimer = setInterval(load, 15000);
  if (!checkWriteFirst) {
    const token = githubToken;
    probe.catch(error => {
      // Coupure passagère : le premier enregistrement le dira. Jeton expiré ou en lecture seule : retour à la connexion.
      if (error.network || token !== githubToken) return;
      logout();
      $('#loginError').textContent = error.message;
      $('#loginError').classList.remove('hidden');
    });
  }
}
async function signIn(prepare, checkWriteFirst) {
  const buttons = document.querySelectorAll('#login button[type=submit]');
  for (const button of buttons) button.disabled = true;
  $('#loginError').classList.add('hidden');
  try {
    if (!crypto?.subtle) throw Error('Un navigateur HTTPS récent est requis pour signer les licences.');
    await prepare();
    await openSession(checkWriteFirst);
  } catch (error) {
    clearCredentials();
    $('#serverState').textContent = 'GitHub : connexion requise';
    $('#loginError').textContent = error.message;
    $('#loginError').classList.remove('hidden');
    warmUp();
  } finally {
    $('#loginStatus').textContent = '';
    for (const button of buttons) button.disabled = false;
  }
  return false;
}
function loginWithPassword(event) {
  event.preventDefault();
  return signIn(async () => {
    const user = normalizeUser($('#loginUser').value), password = $('#loginPassword').value;
    progress('Recherche de votre accès…');
    const file = (earlyAccess?.user === user ? await earlyAccess.file : null) || await fetchAccessFile(user);
    // Gardé pour un nouvel essai après une faute de frappe dans le mot de passe.
    earlyAccess = { user, file: Promise.resolve(file) };
    progress('Vérification du mot de passe…');
    const secret = await openAccessFile(file, user, password);
    githubToken = secret.token;
    keyBytes = unbase64(secret.key);
    accessUser = user;
  }, false);
}
function login(event) {
  event.preventDefault();
  return signIn(async () => {
    const file = $('#signingKey').files[0];
    if (!file || file.size > 16384) throw Error('Choisissez la clé .pk8 du serveur (16 Ko maximum).');
    githubToken = $('#githubToken').value.trim();
    keyBytes = new Uint8Array(await file.arrayBuffer());
  }, true);
}
function logout() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  clearCredentials();
  items = [];
  earlyAccess = null;
  $('#rows').innerHTML = '';
  for (const id of ['githubToken', 'signingKey', 'loginPassword']) $(`#${id}`).value = '';
  $('#app').classList.add('hidden');
  $('#headerActions').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#serverState').textContent = 'GitHub : connexion requise';
  warmUp();
}
async function load(manual = false) {
  if (!githubToken || busy || loading || $('#confirmBox').open || $('#requestBox').open ||
      $('#details').open || $('#accessBox').open) return;
  loading = true;
  if (manual) progress('Actualisation…');
  try {
    const snapshot = await readSnapshot();
    items = snapshot.records;
    headSha = snapshot.head;
    ready = true;
    $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
    render();
  } catch (error) {
    // Une coupure passagère ne bloque pas la page : la liste affichée reste utilisable et chaque enregistrement
    // revérifie de toute façon la version de la base sur GitHub.
    if (!error.network) ready = false;
    $('#serverState').textContent = error.network
      ? 'GitHub momentanément injoignable · nouvel essai automatique' : 'GitHub : actualisation échouée';
    if (manual || !error.network) message(error.message, true);
    render();
  } finally { loading = false; }
}

async function publishedPath(record) {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(record.installationId)));
  const suffix = Array.from(hash.slice(0, 12), byte => byte.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `licenses/${normalizeMachine(record.machineCode)}-${suffix}.lic`;
}
async function signed(payload) {
  const bytes = encoder.encode(JSON.stringify(payload));
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, signingKey, bytes));
  if (signature.length !== 64) throw Error('Signature ECDSA inattendue.');
  return `${url64(bytes)}.${url64(signature)}`;
}
async function publication(record) {
  const path = await publishedPath(record);
  if (record.status === 'Revoked')
    return { path, content: JSON.stringify({ status: 'revoked', revocationToken: await signed({
      LicenseId: record.id, MachineCode: normalizeMachine(record.machineCode),
      InstallationId: record.installationId, GrantVersion: record.revision,
      RevokedAtUtc: record.decidedAtUtc,
    }) }, null, 2) + '\n' };
  if (record.status !== 'Approved') return null;
  const days = record.kind === 'Trial15' ? 15 : record.kind === 'Trial30' ? 30 : null;
  if (days === null && record.kind !== 'Permanent') throw Error('Type de licence inconnu.');
  if (days !== null && (!record.expiresAtUtc || new Date(record.expiresAtUtc) <= new Date()))
    throw Error("L'essai est déjà expiré : choisissez Renouveler.");
  const issued = days === null ? new Date().toISOString()
    : new Date(new Date(record.expiresAtUtc).getTime() - days * 86400000).toISOString();
  const token = await signed({
    LicenseId: record.id, MachineCode: normalizeMachine(record.machineCode),
    InstallationId: record.installationId, IssuedAtUtc: issued,
    ExpiresAtUtc: days === null ? null : record.expiresAtUtc,
    Kind: record.kind, GrantVersion: record.revision,
    Features: effectiveFeatures(record) ?? null,
  });
  return { path, content: JSON.stringify({ status: 'active', token }, null, 2) + '\n' };
}

async function commitSnapshot(records, published) {
  if (!ready || !headSha) throw Error('Base GitHub non chargée ; actualisez la page.');
  const current = await github('GET', `/git/ref/heads/${BRANCH}`);
  if (current.object.sha !== headSha) {
    const error = new Error('Une autre modification a eu lieu sur GitHub : rechargez la liste avant de confirmer.');
    error.status = 409;
    throw error;
  }
  const snapshot = await encrypt(records);
  const files = [{ path: DATABASE, content: JSON.stringify(snapshot, null, 2) + '\n' }];
  if (published) files.push(published);
  const parent = await github('GET', `/git/commits/${headSha}`);
  const entries = [];
  for (const file of files) {
    const blob = await github('POST', '/git/blobs',
      { content: base64(encoder.encode(file.content)), encoding: 'base64' });
    entries.push({ path: file.path, mode: '100644', type: 'blob', sha: blob.sha });
  }
  const tree = await github('POST', '/git/trees', { base_tree: parent.tree.sha, tree: entries });
  const commit = await github('POST', '/git/commits', {
    message: 'Update encrypted STOKY licence decisions',
    tree: tree.sha, parents: [headSha],
  });
  const updated = await github('PATCH', `/git/refs/heads/${BRANCH}`, { sha: commit.sha, force: false });
  headSha = updated.object.sha;
}
async function change(mutator, success, id = null) {
  if (busy) return false;
  if (!ready) {
    message('Base GitHub non chargée : fermez cette fenêtre, actualisez la liste (🔄) puis recommencez.', true);
    return false;
  }
  setBusy(true);
  render();
  message('Enregistrement sur GitHub…');
  try {
    for (let attempt = 0; ; attempt++) {
      const next = structuredClone(items);
      const published = await mutator(next);
      try {
        await commitSnapshot(next, published);
        items = next;
        message(success);
        return true;
      } catch (error) {
        if ((error.status !== 409 && error.status !== 422) || attempt >= 2) throw error;
        // Le dépôt a avancé (autre onglet, publication de la page) : relire la base puis rejouer la modification.
        const revision = id ? items.find(x => x.id === id)?.revision : null;
        const snapshot = await readSnapshot();
        items = snapshot.records;
        headSha = snapshot.head;
        if (id && items.find(x => x.id === id)?.revision !== revision)
          throw Error('Cette installation a été modifiée ailleurs entre-temps : vérifiez-la, puis recommencez.');
      }
    }
  } catch (error) {
    message(error.message, true);
    return false;
  } finally {
    setBusy(false);
    if (ready) $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
    render();
  }
}

function status(record) {
  if (record.archived || record.status === 'Revoked') return 'Revoked';
  if (record.status !== 'Approved') return record.status;
  if (record.kind === 'Permanent') return record.expiresAtUtc ? 'ReviewRequired' : 'Approved';
  const days = record.kind === 'Trial15' ? 15 : record.kind === 'Trial30' ? 30 : null;
  if (!days || !record.expiresAtUtc ||
      new Date(record.expiresAtUtc) - new Date(record.decidedAtUtc || record.requestedAtUtc) > days * 86400000)
    return 'ReviewRequired';
  return new Date(record.expiresAtUtc) <= new Date() ? 'Expired' : 'Approved';
}
function kindLabel(record) {
  if (record.status !== 'Approved' && record.status !== 'Revoked') return '-';
  return (kindNames[record.kind] || 'À vérifier') +
    (record.expiresAtUtc ? ' — échéance ' + date(record.expiresAtUtc) : ' — sans échéance');
}
function clearFilters() {
  for (const id of ['search', 'dateFrom', 'dateTo', 'statusFilter', 'kindFilter']) $(`#${id}`).value = '';
  $('#duplicates').checked = false;
  render();
}
function render() {
  if ($('#confirmBox').open) return;
  const query = $('#search').value.trim().toLocaleLowerCase();
  const filter = $('#statusFilter').value, kind = $('#kindFilter').value;
  const from = $('#dateFrom').value ? new Date($('#dateFrom').value + 'T00:00:00') : null;
  const to = $('#dateTo').value ? new Date($('#dateTo').value + 'T23:59:59.999') : null;
  const duplicates = new Map();
  for (const record of items.filter(x => !x.archived)) {
    if (!duplicates.has(record.machineCode)) duplicates.set(record.machineCode, new Set());
    duplicates.get(record.machineCode).add(record.installationId);
  }
  const visible = items.filter(x => ($('#archived').checked || !x.archived) &&
    (!filter || status(x) === filter) && (!kind || x.kind === kind) &&
    (!$('#duplicates').checked || (duplicates.get(x.machineCode)?.size || 0) > 1) &&
    (!query || [x.customerName, x.phoneNumber, (x.phoneNumber || '').replace(/\D/g, '')]
      .join(' ').toLocaleLowerCase().includes(query.replace(/\s+/g, ' '))) &&
    (!from || new Date(x.requestedAtUtc) >= from) && (!to || new Date(x.requestedAtUtc) <= to))
    .sort((a, b) => (status(b) === 'Pending') - (status(a) === 'Pending') ||
      new Date(b.requestedAtUtc) - new Date(a.requestedAtUtc));
  const pending = items.filter(x => status(x) === 'Pending' && !x.archived).length;
  $('#summary').textContent = `${visible.length} / ${items.length}`;
  $('#pendingCount').textContent = pending ? `⏳ ${pending} En Attente` : '';
  $('#pendingCount').classList.toggle('hidden', !pending);
  document.title = (pending ? `(${pending}) ` : '') + 'STOKY Pro - Licences (GitHub)';
  const btn = (cls, title, icon, action) =>
    `<button class="${cls} ic" title="${esc(title)}" aria-label="${esc(title)}" ${ready && !busy ? '' : 'disabled'} onclick="${action}">${icon}</button>`;
  $('#rows').innerHTML = visible.map(x => {
    const st = status(x), isPending = st === 'Pending';
    const duplicate = (duplicates.get(x.machineCode)?.size || 0) > 1;
    const actions = btn('info', 'Détails et coordonnées', 'ℹ️', `details('${x.id}')`) + (x.archived ? '' :
      btn('trial', 'Essai 15 jours', '⏳<small>15</small>', `decide('${x.id}','approve15')`) +
      btn('trial', 'Essai 30 jours', '⏳<small>30</small>', `decide('${x.id}','approve30')`) +
      btn('approve', 'Licence permanente', '✅', `decide('${x.id}','approve')`) +
      (x.status === 'Approved' && x.kind !== 'Permanent'
        ? btn('trial', "Renouveler l'essai", '🔁', `decide('${x.id}','${x.kind === 'Trial15' ? 'approve15' : 'approve30'}',true)`) : '') +
      (isPending ? btn('reject', 'Refuser la demande', '❌', `decide('${x.id}','reject')`) : '') +
      (x.status !== 'Revoked' ? btn('revoke', 'Révoquer la licence', '🚫', `decide('${x.id}','revoke')`) : '') +
      btn('delete', 'Archiver cette installation', '🗑', `removeActivation('${x.id}')`));
    return `<tr class="${duplicate ? 'duplicate ' : ''}${isPending ? 'pending' : ''}">
      <td data-label="Abonné"><b>${esc(x.customerName || 'Sans nom')}</b><br>${esc(x.phoneNumber || '-')}<br>
        <small>Demande : ${date(x.requestedAtUtc)}</small><br>
        <small>🏷 ${esc(DOMAINS[x.domain] || 'Domaine non précisé')} · ⚙️ ${esc(featuresSummary(x))}</small></td>
      <td data-label="Machine"><code>${esc(x.machineCode)}</code><br>
        <small>${esc(x.deviceName || 'Poste non signalé')} · ${esc(x.installationId)}</small>
        ${duplicate ? '<br><span class="duplicate-note">Doublon possible</span>' : ''}
        ${x.archived ? '<br><b>Archivée</b>' : ''}</td>
      <td data-label="Vu" class="seen">${date(x.lastSeenAtUtc)}<small>${ago(x.lastSeenAtUtc)}</small></td>
      <td data-label="Licence">${isPending ? '<span class="badge b-Pending">⏳ En Attente</span>' :
        `${esc(kindLabel(x))}<br><span class="badge b-${st}">${labels[st] || st}</span><br>
         <small>Décision v${x.revision} · ${date(x.decidedAtUtc)}</small>`}</td>
      <td data-label="Options">${esc(featuresSummary(x))}</td>
      <td data-label="Actions" class="actions">${actions}</td></tr>`;
  }).join('');
}

function ask(title, text, label = 'Confirmer', danger = false) {
  return new Promise(resolve => {
    const box = $('#confirmBox'), ok = $('#confirmOk'), cancel = $('#confirmCancel');
    $('#confirmTitle').textContent = title;
    $('#confirmText').textContent = text;
    ok.textContent = '✔ ' + label;
    ok.className = danger ? 'revoke' : 'approve';
    const finish = value => {
      ok.onclick = cancel.onclick = box.onclose = null;
      if (box.open) box.close();
      resolve(value);
    };
    ok.onclick = () => finish(true);
    cancel.onclick = box.onclose = () => finish(false);
    box.showModal();
    cancel.focus();
  });
}
function openRequest() {
  for (const element of document.querySelectorAll('#requestBox .dialog-message')) element.textContent = '';
  $('#requestBox').showModal();
  $('#requestCode').focus();
}
async function addRequest() {
  try {
    const code = JSON.parse($('#requestCode').value);
    const machineCode = normalizeMachine(code.machineCode);
    const installationId = typeof code.installationId === 'string' ? code.installationId.trim() : null;
    if (!/^[0-9A-F]{16}$/.test(machineCode) ||
        typeof installationId !== 'string' || !installationId.length || installationId.length > 128)
      throw Error("La demande doit contenir un code machine et un identifiant d'installation valides.");
    if (code.domain != null && !DOMAINS[code.domain])
      throw Error("Le domaine de la demande n'est pas connu.");
    if (code.features != null && (!Array.isArray(code.features) ||
        code.features.some(feature => !FEATURES.some(item => item[0] === feature))))
      throw Error("Une option demandée n'est pas connue.");
    if (items.some(x => !x.archived && normalizeMachine(x.machineCode) === machineCode &&
        x.installationId === installationId))
      throw Error('Cette installation existe déjà ; utilisez sa ligne pour accorder ou révoquer la licence.');
    const record = {
      id: crypto.randomUUID(), machineCode, installationId,
      customerName: $('#requestName').value.trim() || null,
      phoneNumber: $('#requestPhone').value.trim() || null,
      status: 'Pending', kind: 'Permanent', expiresAtUtc: null,
      requestedAtUtc: new Date().toISOString(), decidedAtUtc: null, revision: 0,
      archived: false, domain: code.domain ?? null,
      requestedFeatures: code.features ?? null, grantedFeatures: null,
      lastSeenAtUtc: null, clientLicenseStatus: 'Unknown', history: [],
    };
    if (await change(async next => {
      if (next.some(x => !x.archived && normalizeMachine(x.machineCode) === machineCode &&
          x.installationId === installationId))
        throw Error('Cette installation existe déjà ; utilisez sa ligne pour accorder ou révoquer la licence.');
      next.unshift(record);
      return null;
    },
      'Demande enregistrée sur GitHub ; le poste peut rester hors ligne jusqu’à la décision.')) {
      $('#requestBox').close();
      $('#requestCode').value = '';
    }
  } catch (error) { message(error.message, true); }
}
async function decide(id, decision, renew = false) {
  if (busy) return;
  if (!ready) { message('Base GitHub non chargée : actualisez la liste (🔄) puis recommencez.', true); return; }
  const record = items.find(x => x.id === id);
  if (!record || record.archived) { message('Installation introuvable.', true); return; }
  const days = decision === 'approve15' ? 15 : decision === 'approve30' ? 30 : 0;
  const kind = days ? `Essai ${days} jours` : 'Permanente';
  const who = `${record.customerName || 'Abonné sans nom'} · ${record.phoneNumber || '-'}\nMachine : ${record.machineCode}`;
  const sameKind = record.status === 'Approved' && record.kind === (days ? `Trial${days}` : 'Permanent');
  if (decision.startsWith('approve') && !renew && sameKind) {
    message('Cette licence est déjà accordée ; aucune échéance ne change.');
    return;
  }
  if (decision === 'revoke' && record.status === 'Revoked') {
    message('Cette licence est déjà révoquée.');
    return;
  }
  const start = renew ? new Date() : new Date(record.requestedAtUtc);
  const expiry = days ? new Date(start.getTime() + days * 86400000) : null;
  const title = decision === 'revoke' ? 'Révoquer la licence' :
    decision === 'reject' ? 'Refuser la demande'
      : `${!renew ? 'Accorder' : sameKind ? 'Renouveler' : 'Changer le type'} : ${kind}`;
  const text = who + (decision === 'revoke'
    ? '\n\nLa licence sera retirée à la prochaine connexion du poste. Un poste hors ligne reste actif jusque-là.'
    : decision === 'reject' ? '\n\nLe poste restera sans licence.'
      : days ? `\n\nDébut : ${date(start)}\nÉchéance : ${date(expiry)}` +
          (expiry <= new Date() ? '\n⚠ Essai déjà expiré : utilisez Renouveler.' : '')
        : '\n\nLicence permanente sans échéance, jusqu’à révocation manuelle.') +
    (record.status !== 'Pending' && decision.startsWith('approve') ? '\n\nCette décision remplace la précédente.' : '');
  if (!await ask(title, text, decision === 'revoke' ? 'Révoquer' : 'Confirmer',
    decision === 'revoke' || decision === 'reject')) return;
  await change(async next => {
    const x = next.find(item => item.id === id);
    if (!x || x.archived) throw Error('Installation introuvable.');
    if (decision === 'reject' && x.status !== 'Pending') throw Error('Seule une demande en attente peut être refusée.');
    const now = new Date().toISOString();
    x.revision++;
    x.decidedAtUtc = now;
    if (decision === 'revoke') x.status = 'Revoked';
    else if (decision === 'reject') x.status = 'Rejected';
    else {
      x.status = 'Approved';
      x.kind = days ? `Trial${days}` : 'Permanent';
      x.expiresAtUtc = expiry ? expiry.toISOString() : null;
    }
    x.history = [...(x.history || []), { atUtc: now,
      action: decision === 'revoke' ? 'Revoked' : decision === 'reject' ? 'Rejected' :
        renew && sameKind ? 'Renewed' : 'Approved',
      actor: 'GitHub', kind: x.kind, expiresAtUtc: x.expiresAtUtc }];
    return publication(x);
  }, 'Décision enregistrée sur GitHub. Le poste la recevra à sa prochaine connexion.', id);
}
async function changeKind(decision) {
  const record = items.find(x => x.id === selectedId);
  if (!record) return;
  $('#details').close();
  // Une installation déjà décidée change de type à partir d'aujourd'hui ; une demande en attente part de sa date.
  await decide(record.id, decision, decision !== 'approve' && decision !== 'revoke' && record.status !== 'Pending');
}
async function removeActivation(id) {
  const record = items.find(x => x.id === id);
  if (!record || busy) return;
  if (!ready) { message('Base GitHub non chargée : actualisez la liste (🔄) puis recommencez.', true); return; }
  if (!await ask('Archiver cette installation',
    `${record.customerName || 'Abonné sans nom'} · ${record.machineCode}\n\nLa licence sera révoquée ; sa trace restera chiffrée pour empêcher la réutilisation de l'ancien code.`,
    'Archiver', true)) return;
  await change(async next => {
    const x = next.find(item => item.id === id);
    if (!x) throw Error('Installation introuvable.');
    const now = new Date().toISOString();
    x.status = 'Revoked';
    x.archived = true;
    x.decidedAtUtc = now;
    x.revision++;
    x.history = [...(x.history || []), { atUtc: now, action: 'Archived',
      actor: 'GitHub', kind: x.kind, expiresAtUtc: x.expiresAtUtc }];
    return publication(x);
  }, 'Installation archivée et révocation publiée.', id);
}
function details(id) {
  const record = items.find(x => x.id === id);
  if (!record) return;
  selectedId = id;
  for (const element of document.querySelectorAll('#details .dialog-message')) element.textContent = '';
  $('#kindBox')?.classList.toggle('hidden', !!record.archived);
  $('#editName').value = record.customerName || '';
  $('#editPhone').value = record.phoneNumber || '';
  const requested = record.requestedFeatures, granted = effectiveFeatures(record);
  $('#featuresLegend').textContent = `Options accordées — domaine : ${DOMAINS[record.domain] || 'non précisé'}`;
  $('#featureList').innerHTML = FEATURES.map(([code, label]) =>
    `<label style="display:flex;gap:6px;align-items:center;margin:0">
      <input type="checkbox" class="feature" value="${code}" ${granted == null || granted.includes(code) ? 'checked' : ''}>
      ${esc(label)}${requested && !requested.includes(code) ? ' <small>(non demandée)</small>' : ''}</label>`).join('');
  $('#detailText').textContent =
    `ID de demande : ${record.id}\nMachine : ${record.machineCode}\nInstallation : ${record.installationId}` +
    `\nPoste : ${record.deviceName || '-'}\nDomaine : ${DOMAINS[record.domain] || '-'}` +
    `\nLicence : ${kindLabel(record)}\nÉtat : ${labels[status(record)] || status(record)} — version ${record.revision}` +
    `\nPremière demande : ${date(record.requestedAtUtc)}\nDécidée : ${date(record.decidedAtUtc)}` +
    `\nDernière connexion connue (ancien serveur) : ${date(record.lastSeenAtUtc)}` +
    `\n\nHistorique :\n` + (record.history || []).map(event =>
      `${date(event.atUtc)} · ${event.actor} · ${event.action} · ${kindNames[event.kind] || event.kind}`).join('\n');
  $('#details').showModal();
}
async function saveContact() {
  if (!selectedId) return;
  const name = $('#editName').value.trim(), phone = $('#editPhone').value.trim();
  if (await change(async next => {
    const record = next.find(x => x.id === selectedId);
    if (!record) throw Error('Installation introuvable.');
    record.customerName = name || null;
    record.phoneNumber = phone || null;
    return null;
  }, 'Coordonnées chiffrées enregistrées sans changer la licence.', selectedId)) $('#details').close();
}
async function saveFeatures() {
  if (!selectedId) return;
  const features = [...document.querySelectorAll('#featureList .feature:checked')].map(input => input.value);
  if (await change(async next => {
    const record = next.find(x => x.id === selectedId);
    if (!record) throw Error('Installation introuvable.');
    record.grantedFeatures = features;
    record.revision++;
    record.history = [...(record.history || []), { atUtc: new Date().toISOString(),
      action: 'FeaturesUpdated', actor: 'GitHub', kind: record.kind, expiresAtUtc: record.expiresAtUtc }];
    return record.status === 'Approved' ? publication(record) : null;
  }, 'Options accordées enregistrées et nouvelle licence signée.', selectedId)) $('#details').close();
}
async function copyId() {
  try { await navigator.clipboard.writeText(selectedId); message('ID copié.'); }
  catch (error) { message('Copie impossible : ' + error.message, true); }
}

function openAccess() {
  for (const element of document.querySelectorAll('#accessBox .dialog-message')) element.textContent = '';
  $('#accessUser').value = accessUser;
  $('#accessPassword').value = $('#accessConfirm').value = '';
  $('#accessBox').showModal();
  $(accessUser ? '#accessPassword' : '#accessUser').focus();
}
async function accessFileSha(path) {
  try { return (await github('GET', `/contents/docs/${path}?ref=${BRANCH}`)).sha; }
  catch (error) { if (error.status === 404) return null; throw error; }
}
async function accessChange(action, success) {
  if (busy) return;
  if (!ready) { message('Base GitHub non chargée : fermez cette fenêtre, actualisez la liste (🔄) puis recommencez.', true); return; }
  setBusy(true);
  message('Enregistrement sur GitHub…');
  try {
    if (await action() === false) return;
    // La publication a créé un commit : la liste repart de cette version.
    const snapshot = await readSnapshot();
    items = snapshot.records;
    headSha = snapshot.head;
    $('#accessPassword').value = $('#accessConfirm').value = '';
    message(success);
  } catch (error) {
    message(error.message, true);
  } finally {
    setBusy(false);
    $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
    render();
  }
}
function saveAccess() {
  const user = normalizeUser($('#accessUser').value), password = $('#accessPassword').value;
  if (!/^[a-z0-9._-]{3,40}$/.test(user)) {
    message('Identifiant : 3 à 40 caractères parmi les lettres sans accent, chiffres, point, tiret et tiret bas.', true);
    return;
  }
  if (password.length < ACCESS_PASSWORD_LENGTH) {
    message(`Le mot de passe doit contenir au moins ${ACCESS_PASSWORD_LENGTH} caractères.`, true);
    return;
  }
  if (password !== $('#accessConfirm').value) { message('Les deux mots de passe ne correspondent pas.', true); return; }
  return accessChange(async () => {
    const path = await accessPath(user);
    const file = await sealAccess(user, password);
    await github('PUT', `/contents/docs/${path}`, {
      message: 'Update password-protected licence administration access',
      content: base64(encoder.encode(JSON.stringify(file, null, 2) + '\n')),
      branch: BRANCH, ...(await accessFileSha(path).then(sha => sha ? { sha } : {})),
    });
    accessUser = user;
    earlyAccess = null;
  }, `Connexion par mot de passe enregistrée pour « ${user} ». Elle est utilisable tout de suite ` +
     '(jusqu\'à une minute après sa création).');
}
async function deleteAccess() {
  const user = normalizeUser($('#accessUser').value);
  if (!user) { message("Indiquez l'identifiant à supprimer.", true); return; }
  if (!await ask('Supprimer la connexion par mot de passe',
    `Identifiant : ${user}\n\nLe jeton et la clé chiffrés seront retirés de GitHub. La connexion avec le jeton et le fichier de clé reste possible.`,
    'Supprimer', true)) return;
  return accessChange(async () => {
    const path = await accessPath(user);
    const sha = await accessFileSha(path);
    if (!sha) { message(`Aucune connexion par mot de passe pour « ${user} ».`, true); return false; }
    await github('DELETE', `/contents/docs/${path}`, {
      message: 'Remove password-protected licence administration access', sha, branch: BRANCH });
    if (accessUser === user) accessUser = '';
  }, `Connexion par mot de passe supprimée pour « ${user} ».`);
}

// Dès l'ouverture : la base chiffrée et le fichier d'accès de l'identifiant saisi sont préparés pendant la frappe.
$('#loginUser').addEventListener('change', prepareAccess);
$('#loginPassword').addEventListener('focus', () => { prepareAccess(); warmUp(); });
setTimeout(prepareAccess, 600);
warmUp();
