'use strict';

const $ = selector => document.querySelector(selector);
const REPO = 'zwalid2-ux/gestion-stock-licences';
const API = `https://api.github.com/repos/${REPO}`;
const BRANCH = 'main';
const DATABASE = 'admin/activations.v1.enc.json';
const KEY_INFO = 'STOKY GitHub licence store v1';
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
let ready = false;

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
function message(text, error = false) {
  $('#message').textContent = text;
  $('#message').classList.toggle('error', error);
}
function clearCredentials() {
  githubToken = '';
  signingKey = null;
  publicKey = null;
  if (keyBytes) keyBytes.fill(0);
  keyBytes = null;
  headSha = null;
  ready = false;
}

async function github(method, path, body) {
  const response = await fetch(API + path, {
    method, cache: 'no-store',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${githubToken}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    const error = new Error(`GitHub (${response.status}) : ${detail?.message || response.statusText}`);
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
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

async function readSnapshot() {
  const ref = await github('GET', `/git/ref/heads/${BRANCH}`);
  const head = ref.object.sha;
  let file;
  try {
    file = await github('GET', `/contents/${DATABASE}?ref=${encodeURIComponent(head)}`);
  } catch (error) {
    if (error.status === 404)
      throw Error("Base GitHub absente : exportez d'abord la base du serveur avec --export-github. Aucune base vide ne sera créée.");
    throw error;
  }
  if (file.encoding !== 'base64' || typeof file.content !== 'string')
    throw Error('GitHub a renvoyé un format de base inattendu.');
  const records = await decrypt(JSON.parse(decoder.decode(unbase64(file.content))));
  if (!Array.isArray(records) || records.some(record =>
    !/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(record.id) ||
    !/^[0-9a-f]{16}$/i.test(normalizeMachine(record.machineCode)) ||
    typeof record.installationId !== 'string' || !record.installationId.length ||
    !Number.isInteger(record.revision) || record.revision < 0))
    throw Error('La base GitHub contient des installations invalides ; aucune modification ne sera faite.');
  return { head, records };
}

async function login(event) {
  event.preventDefault();
  const button = $('#loginButton');
  button.disabled = true;
  $('#loginError').classList.add('hidden');
  try {
    if (!crypto?.subtle) throw Error('Un navigateur HTTPS récent est requis pour signer les licences.');
    const file = $('#signingKey').files[0];
    if (!file || file.size > 16384) throw Error('Choisissez la clé .pk8 du serveur (16 Ko maximum).');
    githubToken = $('#githubToken').value.trim();
    keyBytes = new Uint8Array(await file.arrayBuffer());
    signingKey = await crypto.subtle.importKey('pkcs8', keyBytes,
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const repo = await github('GET', '');
    if (!repo.permissions?.push)
      throw Error("Ce jeton GitHub n'a pas le droit d'écrire dans le dépôt des licences.");
    const snapshot = await readSnapshot();
    items = snapshot.records;
    headSha = snapshot.head;
    ready = true;
    $('#githubToken').value = '';
    $('#signingKey').value = '';
    $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    $('#headerActions').classList.remove('hidden');
    render();
    if (!pollTimer) pollTimer = setInterval(load, 15000);
  } catch (error) {
    clearCredentials();
    $('#serverState').textContent = 'GitHub : connexion requise';
    $('#loginError').textContent = error.message;
    $('#loginError').classList.remove('hidden');
  } finally { button.disabled = false; }
  return false;
}
function logout() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  clearCredentials();
  items = [];
  $('#githubToken').value = '';
  $('#signingKey').value = '';
  $('#app').classList.add('hidden');
  $('#headerActions').classList.add('hidden');
  $('#login').classList.remove('hidden');
  $('#serverState').textContent = 'GitHub : connexion requise';
}
async function load() {
  if (!githubToken || busy || loading || $('#confirmBox').open || $('#requestBox').open || $('#details').open) return;
  loading = true;
  try {
    const snapshot = await readSnapshot();
    items = snapshot.records;
    headSha = snapshot.head;
    ready = true;
    $('#serverState').textContent = 'GitHub connecté · base chiffrée chargée';
    render();
  } catch (error) {
    ready = false;
    $('#serverState').textContent = 'GitHub : actualisation échouée';
    message(error.message, true);
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
async function change(mutator, success) {
  if (!ready || busy) return false;
  busy = true;
  let conflict = false;
  try {
    const next = structuredClone(items);
    const published = await mutator(next);
    await commitSnapshot(next, published);
    items = next;
    message(success);
    return true;
  } catch (error) {
    conflict = error.status === 409 || error.status === 422;
    if (conflict) ready = false;
    message(error.message, true);
    return false;
  } finally {
    busy = false;
    render();
    if (conflict) setTimeout(load, 0);
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
function openRequest() { $('#requestBox').showModal(); $('#requestCode').focus(); }
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
    if (await change(async next => { next.unshift(record); return null; },
      'Demande enregistrée sur GitHub ; le poste peut rester hors ligne jusqu’à la décision.')) {
      $('#requestBox').close();
      $('#requestCode').value = '';
    }
  } catch (error) { message(error.message, true); }
}
async function decide(id, decision, renew = false) {
  if (!ready || busy) return;
  const record = items.find(x => x.id === id);
  if (!record || record.archived) { message('Installation introuvable.', true); return; }
  const days = decision === 'approve15' ? 15 : decision === 'approve30' ? 30 : 0;
  const kind = days ? `Essai ${days} jours` : 'Permanente';
  const who = `${record.customerName || 'Abonné sans nom'} · ${record.phoneNumber || '-'}\nMachine : ${record.machineCode}`;
  if (decision.startsWith('approve') && !renew && record.status === 'Approved' &&
      record.kind === (days ? `Trial${days}` : 'Permanent')) {
    message('Cette licence est déjà accordée ; aucune échéance ne change.');
    return;
  }
  const start = renew ? new Date() : new Date(record.requestedAtUtc);
  const expiry = days ? new Date(start.getTime() + days * 86400000) : null;
  const title = decision === 'revoke' ? 'Révoquer la licence' :
    decision === 'reject' ? 'Refuser la demande' : `${renew ? 'Renouveler' : 'Accorder'} : ${kind}`;
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
        renew ? 'Renewed' : 'Approved',
      actor: 'GitHub', kind: x.kind, expiresAtUtc: x.expiresAtUtc }];
    return publication(x);
  }, 'Décision enregistrée sur GitHub. Le poste la recevra à sa prochaine connexion.');
}
async function removeActivation(id) {
  const record = items.find(x => x.id === id);
  if (!record || !ready || busy) return;
  if (!await ask('Archiver cette installation',
    `${record.customerName || 'Abonné sans nom'} · ${record.machineCode}\n\nLa licence sera révoquée ; sa trace restera chiffrée pour empêcher la réutilisation de l'ancien code.`,
    'Archiver', true)) return;
  await change(async next => {
    const x = next.find(item => item.id === id);
    const now = new Date().toISOString();
    x.status = 'Revoked';
    x.archived = true;
    x.decidedAtUtc = now;
    x.revision++;
    x.history = [...(x.history || []), { atUtc: now, action: 'Archived',
      actor: 'GitHub', kind: x.kind, expiresAtUtc: x.expiresAtUtc }];
    return publication(x);
  }, 'Installation archivée et révocation publiée.');
}
function details(id) {
  const record = items.find(x => x.id === id);
  if (!record) return;
  selectedId = id;
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
  }, 'Coordonnées chiffrées enregistrées sans changer la licence.')) $('#details').close();
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
  }, 'Options accordées enregistrées et nouvelle licence signée.')) $('#details').close();
}
async function copyId() {
  try { await navigator.clipboard.writeText(selectedId); message('ID copié.'); }
  catch (error) { message('Copie impossible : ' + error.message, true); }
}
