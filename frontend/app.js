'use strict';

// Redirect to login if no token present; decode to check mustChangePassword
const _token = localStorage.getItem('auth_token');
if (!_token) {
  window.location.replace('login.html');
} else {
  try {
    const _payload = JSON.parse(atob(_token.split('.')[1]));
    if (_payload.mustChangePassword) {
      window.location.replace('change-password.html');
    }
  } catch { /* malformed token — 401 from API will handle it */ }
}

const API_BASE = '/api/passwords';

// Auto-logout after 2 minutes of inactivity
const LOGOUT_TIMEOUT_MS = 2 * 60 * 1000;
let _inactivityTimer = setTimeout(doInactivityLogout, LOGOUT_TIMEOUT_MS);

function doInactivityLogout() {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_username');
  localStorage.removeItem('auth_isAdmin');
  window.location.replace('login.html?timeout=1');
}

function resetInactivityTimer() {
  clearTimeout(_inactivityTimer);
  _inactivityTimer = setTimeout(doInactivityLogout, LOGOUT_TIMEOUT_MS);
}

['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'].forEach(evt =>
  document.addEventListener(evt, resetInactivityTimer, { passive: true })
);

function authFetch(url, options) {
  const token = localStorage.getItem('auth_token');
  const headers = Object.assign({}, options && options.headers, {
    'Authorization': 'Bearer ' + token,
  });
  return fetch(url, Object.assign({}, options, { headers }));
}

function handleUnauthorized() {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_username');
  window.location.replace('login.html');
}

const CHARSET = {
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower:   'abcdefghijklmnopqrstuvwxyz',
  digits:  '0123456789',
  special: '!@#$%^*()-_=+[]{}|:,.?',
};
const ALL_CHARS = CHARSET.upper + CHARSET.lower + CHARSET.digits + CHARSET.special;
const PASSWORD_LENGTH = 20;

const form          = document.getElementById('password-form');
const websiteInput  = document.getElementById('website');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const btnGenerate   = document.getElementById('btn-generate');
const btnCopy       = document.getElementById('btn-copy');
const btnSubmit     = document.getElementById('btn-submit');
const btnSpinner    = document.getElementById('btn-spinner');
const btnRefresh    = document.getElementById('btn-refresh');
const alertArea     = document.getElementById('alert-area');
const entriesArea   = document.getElementById('entries-area');
const strengthBar      = document.getElementById('strength-bar');
const strengthLabel    = document.getElementById('strength-label');
const deleteModalEl    = document.getElementById('deleteModal');
const deleteUsernameEl = document.getElementById('delete-username');
const deleteWebsiteWrapEl = document.getElementById('delete-website-wrap');
const deleteWebsiteEl  = document.getElementById('delete-website');
const btnConfirmDelete = document.getElementById('btn-confirm-delete');
const deleteErrorEl    = document.getElementById('delete-error');
const deleteSpinnerEl  = document.getElementById('delete-spinner');

// Cryptographically random integer in [0, max) with rejection sampling to avoid modulo bias
function randomInt(max) {
  const arr = new Uint32Array(1);
  const limit = Math.floor(0xFFFFFFFF / max) * max;
  let val;
  do { crypto.getRandomValues(arr); val = arr[0]; } while (val >= limit);
  return val % max;
}

// Generates a 20-char password guaranteed to include each character class,
// then Fisher-Yates shuffles to avoid predictable positions.
function generatePassword() {
  const mandatory = [
    CHARSET.upper[randomInt(CHARSET.upper.length)],
    CHARSET.lower[randomInt(CHARSET.lower.length)],
    CHARSET.digits[randomInt(CHARSET.digits.length)],
    CHARSET.special[randomInt(CHARSET.special.length)],
  ];
  const rest = Array.from({ length: PASSWORD_LENGTH - mandatory.length },
    () => ALL_CHARS[randomInt(ALL_CHARS.length)]);
  const combined = [...mandatory, ...rest];
  for (let i = combined.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [combined[i], combined[j]] = [combined[j], combined[i]];
  }
  return combined.join('');
}

function measureStrength(pw) {
  if (!pw) return { score: 0, label: '' };
  let score = 0;
  if (pw.length >= 8)         score += 20;
  if (pw.length >= 12)        score += 10;
  if (/[a-z]/.test(pw))       score += 15;
  if (/[A-Z]/.test(pw))       score += 15;
  if (/[0-9]/.test(pw))       score += 15;
  if (/[^a-zA-Z0-9]/.test(pw)) score += 25;
  const label = score <= 30 ? 'Weak' : score <= 55 ? 'Fair' : score <= 75 ? 'Good' : 'Strong';
  return { score, label };
}

function updateStrengthUI(pw) {
  const { score, label } = measureStrength(pw);
  strengthBar.style.width = `${Math.min(score, 100)}%`;
  strengthBar.setAttribute('aria-valuenow', score);
  strengthBar.className = 'progress-bar '
    + (score <= 30 ? 'bg-danger' : score <= 55 ? 'bg-warning' : score <= 75 ? 'bg-info' : 'bg-success');
  strengthLabel.textContent = label;
  strengthLabel.className = 'fw-semibold '
    + (score <= 30 ? 'text-danger' : score <= 55 ? 'text-warning' : score <= 75 ? 'text-info' : 'text-success');
}

async function copyToClipboard(text) {
  if (navigator.clipboard) {
    await navigator.clipboard.writeText(text);
    return;
  }
  // Fallback for plain-HTTP (non-secure) contexts where clipboard API is unavailable
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;width:1px;height:1px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  const ok = document.execCommand('copy');
  ta.remove();
  if (!ok) throw new Error('copy failed');
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showAlert(message, type = 'danger') {
  alertArea.innerHTML = `
    <div class="alert alert-${type} alert-dismissible fade show" role="alert">
      ${escapeHtml(message)}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`;
}

function clearAlert() { alertArea.innerHTML = ''; }

function formatDate(iso) {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

// Show current user and wire logout
const currentUserEl = document.getElementById('current-user');
if (currentUserEl) {
  const username = localStorage.getItem('auth_username') || '';
  const isAdmin  = localStorage.getItem('auth_isAdmin') === 'true';
  currentUserEl.textContent = username + (isAdmin ? ' (admin)' : '');
}
document.getElementById('btn-logout')?.addEventListener('click', () => {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('auth_username');
  localStorage.removeItem('auth_isAdmin');
  window.location.replace('login.html');
});

// Show admin panel if user is admin; hide non-admin sections for admins
const isAdminUser = localStorage.getItem('auth_isAdmin') === 'true';
const adminPanelEl = document.getElementById('admin-panel');
if (isAdminUser && adminPanelEl) {
  adminPanelEl.classList.remove('d-none');
  document.getElementById('create-entry-panel')?.classList.add('d-none');
  document.getElementById('saved-entries-panel')?.classList.add('d-none');
}

// ── Admin: user management ────────────────────────────────────────────────────

const usersArea         = document.getElementById('users-area');
const btnRefreshUsers   = document.getElementById('btn-refresh-users');
const deleteUserModalEl = document.getElementById('deleteUserModal');
const deleteUserNameEl  = document.getElementById('delete-user-name');
const btnConfirmDelUser = document.getElementById('btn-confirm-delete-user');
const deleteUserErrorEl = document.getElementById('delete-user-error');
const deleteUserSpinner = document.getElementById('delete-user-spinner');

let deleteUserModal     = null;
let pendingDeleteUserId = null;
let resetPwModal        = null;
let pendingResetPwUserId = null;

async function loadUsers() {
  if (!isAdminUser || !usersArea) return;
  usersArea.innerHTML = '<p class="text-muted text-center mb-0">Loading…</p>';
  try {
    const res = await authFetch('/api/admin/users');
    if (res.status === 401) { handleUnauthorized(); return; }
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const users = await res.json();

    if (!users.length) {
      usersArea.innerHTML = '<p class="text-muted text-center mb-0">No users found.</p>';
      return;
    }

    const myId = JSON.parse(atob(localStorage.getItem('auth_token').split('.')[1])).sub;

    const rows = users.map(u => `
      <tr>
        <td class="text-muted">${escapeHtml(u.id)}</td>
        <td class="fw-semibold">${escapeHtml(u.username)}${u.isAdmin ? ' <span class="badge" style="background:rgba(189,147,249,0.2);color:var(--drac-purple);font-size:0.7rem;">admin</span>' : ''}</td>
        <td class="text-muted small text-nowrap">${escapeHtml(formatDate(u.createdAt))}</td>
        <td class="text-nowrap">
          <button class="btn btn-sm btn-outline-warning btn-reset-pw me-1"
            data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}"
            ${u.id === myId ? 'disabled title="Cannot reset your own password"' : 'title="Force password change"'}>
            <i class="bi bi-key"></i>
          </button>
          <button class="btn btn-sm btn-outline-danger btn-delete-user"
            data-id="${escapeHtml(u.id)}" data-username="${escapeHtml(u.username)}"
            ${u.id === myId ? 'disabled title="Cannot delete your own account"' : 'title="Delete user"'}>
            <i class="bi bi-person-x"></i>
          </button>
        </td>
      </tr>`).join('');

    usersArea.innerHTML = `
      <div class="table-responsive">
        <table class="table table-hover table-sm align-middle mb-0">
          <thead>
            <tr><th>#</th><th>Username</th><th>Joined</th><th></th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    usersArea.innerHTML = `<p class="text-danger text-center mb-0">Failed to load: ${escapeHtml(err.message)}</p>`;
  }
}

if (isAdminUser) {
  btnRefreshUsers?.addEventListener('click', loadUsers);

  document.getElementById('users-area')?.addEventListener('click', e => {
    const deleteBtn = e.target.closest('.btn-delete-user');
    if (deleteBtn && !deleteBtn.disabled) {
      pendingDeleteUserId = deleteBtn.dataset.id;
      deleteUserNameEl.textContent = deleteBtn.dataset.username;
      deleteUserErrorEl.classList.add('d-none');
      deleteUserErrorEl.textContent = '';
      if (!deleteUserModal) deleteUserModal = new bootstrap.Modal(deleteUserModalEl);
      deleteUserModal.show();
      return;
    }

    const resetBtn = e.target.closest('.btn-reset-pw');
    if (resetBtn && !resetBtn.disabled) {
      pendingResetPwUserId = resetBtn.dataset.id;
      document.getElementById('reset-pw-user-name').textContent = resetBtn.dataset.username;
      const resetPwErrorEl = document.getElementById('reset-pw-error');
      resetPwErrorEl.classList.add('d-none');
      resetPwErrorEl.textContent = '';
      if (!resetPwModal) resetPwModal = new bootstrap.Modal(document.getElementById('resetPasswordModal'));
      resetPwModal.show();
    }
  });

  btnConfirmDelUser?.addEventListener('click', async () => {
    if (!pendingDeleteUserId) return;
    deleteUserErrorEl.classList.add('d-none');
    btnConfirmDelUser.disabled = true;
    deleteUserSpinner.classList.remove('d-none');

    try {
      const res = await authFetch(`/api/admin/users/${pendingDeleteUserId}`, { method: 'DELETE' });
      if (res.status === 401) { handleUnauthorized(); return; }
      const data = await res.json();
      if (res.ok) {
        deleteUserModal.hide();
        loadUsers();
      } else {
        deleteUserErrorEl.textContent = data.error || 'Failed to delete user.';
        deleteUserErrorEl.classList.remove('d-none');
      }
    } catch (err) {
      deleteUserErrorEl.textContent = `Network error: ${err.message}`;
      deleteUserErrorEl.classList.remove('d-none');
    } finally {
      btnConfirmDelUser.disabled = false;
      deleteUserSpinner.classList.remove('d-none');
      deleteUserSpinner.classList.add('d-none');
    }
  });

  loadUsers();

  const btnBackup     = document.getElementById('btn-backup');
  const backupSpinner = document.getElementById('backup-spinner');
  const backupIcon    = document.getElementById('backup-icon');
  const backupErrorEl = document.getElementById('backup-error');

  // Reset password confirm
  document.getElementById('btn-confirm-reset-pw')?.addEventListener('click', async () => {
    if (!pendingResetPwUserId) return;
    const resetPwErrorEl  = document.getElementById('reset-pw-error');
    const resetPwSpinner  = document.getElementById('reset-pw-spinner');
    const btnConfirmResetPw = document.getElementById('btn-confirm-reset-pw');
    resetPwErrorEl.classList.add('d-none');
    btnConfirmResetPw.disabled = true;
    resetPwSpinner.classList.remove('d-none');
    try {
      const res = await authFetch(`/api/admin/users/${pendingResetPwUserId}/reset-password`, { method: 'POST' });
      if (res.status === 401) { handleUnauthorized(); return; }
      const data = await res.json();
      if (res.ok) {
        resetPwModal.hide();
      } else {
        resetPwErrorEl.textContent = data.error || 'Failed to reset password.';
        resetPwErrorEl.classList.remove('d-none');
      }
    } catch (err) {
      resetPwErrorEl.textContent = `Network error: ${err.message}`;
      resetPwErrorEl.classList.remove('d-none');
    } finally {
      btnConfirmResetPw.disabled = false;
      resetPwSpinner.classList.add('d-none');
    }
  });

  // Restore backup
  let restoreFile  = null;
  let restoreModal = null;
  const restoreFileInput  = document.getElementById('restore-file-input');
  const restoreFilenameEl = document.getElementById('restore-filename');
  const btnRestoreUpload  = document.getElementById('btn-restore-upload');
  const restoreErrorEl    = document.getElementById('restore-error');
  const restoreSuccessEl  = document.getElementById('restore-success');

  restoreFileInput?.addEventListener('change', () => {
    restoreFile = restoreFileInput.files[0] || null;
    restoreErrorEl.classList.add('d-none');
    restoreSuccessEl.classList.add('d-none');
    if (restoreFile) {
      restoreFilenameEl.textContent = restoreFile.name;
      restoreFilenameEl.classList.remove('d-none');
      btnRestoreUpload.disabled = false;
    } else {
      restoreFilenameEl.classList.add('d-none');
      btnRestoreUpload.disabled = true;
    }
  });

  btnRestoreUpload?.addEventListener('click', () => {
    if (!restoreFile) return;
    document.getElementById('restore-modal-filename').textContent = restoreFile.name;
    if (!restoreModal) restoreModal = new bootstrap.Modal(document.getElementById('restoreModal'));
    restoreModal.show();
  });

  document.getElementById('btn-confirm-restore')?.addEventListener('click', async () => {
    if (!restoreFile) return;
    const confirmRestoreSpinner = document.getElementById('confirm-restore-spinner');
    const btnConfirmRestore     = document.getElementById('btn-confirm-restore');
    btnConfirmRestore.disabled = true;
    confirmRestoreSpinner.classList.remove('d-none');
    try {
      const sql = await restoreFile.text();
      const res = await authFetch('/api/admin/restore', {
        method:  'POST',
        headers: { 'Content-Type': 'text/plain' },
        body:    sql,
      });
      if (res.status === 401) { handleUnauthorized(); return; }
      const data = await res.json();
      restoreModal.hide();
      if (res.ok) {
        restoreSuccessEl.textContent = data.message || 'Backup restored successfully.';
        restoreSuccessEl.classList.remove('d-none');
        restoreFile = null;
        restoreFileInput.value = '';
        restoreFilenameEl.classList.add('d-none');
        btnRestoreUpload.disabled = true;
        loadUsers();
      } else {
        restoreErrorEl.textContent = data.error || `Restore failed (${res.status}).`;
        restoreErrorEl.classList.remove('d-none');
      }
    } catch (err) {
      restoreModal.hide();
      restoreErrorEl.textContent = `Network error: ${escapeHtml(err.message)}`;
      restoreErrorEl.classList.remove('d-none');
    } finally {
      btnConfirmRestore.disabled = false;
      confirmRestoreSpinner.classList.add('d-none');
    }
  });

  btnBackup?.addEventListener('click', async () => {
    backupErrorEl.classList.add('d-none');
    backupErrorEl.textContent = '';
    btnBackup.disabled = true;
    backupSpinner.classList.remove('d-none');
    backupIcon.classList.add('d-none');
    try {
      const res = await authFetch('/api/admin/backup');
      if (res.status === 401) { handleUnauthorized(); return; }
      if (res.status === 429) {
        backupErrorEl.textContent = 'Too many backup requests. Please wait and try again.';
        backupErrorEl.classList.remove('d-none');
        return;
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        backupErrorEl.textContent = data.error || `Backup failed (${res.status}).`;
        backupErrorEl.classList.remove('d-none');
        return;
      }
      let filename = `backup-${new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')}.sql`;
      const cd = res.headers.get('Content-Disposition');
      if (cd) { const m = cd.match(/filename="([^"]+)"/); if (m) filename = m[1]; }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = Object.assign(document.createElement('a'), { href: url, download: filename });
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      backupErrorEl.textContent = `Network error: ${escapeHtml(err.message)}`;
      backupErrorEl.classList.remove('d-none');
    } finally {
      btnBackup.disabled = false;
      backupSpinner.classList.add('d-none');
      backupIcon.classList.remove('d-none');
    }
  });
}

async function loadEntries() {
  entriesArea.innerHTML = '<p class="text-muted text-center mb-0">Loading…</p>';
  try {
    const res = await authFetch(API_BASE);
    if (res.status === 401) { handleUnauthorized(); return; }
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const entries = await res.json();

    if (!entries.length) {
      entriesArea.innerHTML = '<p class="text-muted text-center mb-0">No entries yet.</p>';
      return;
    }

    const rows = entries.map(e => `
      <tr>
        <td class="text-muted">${escapeHtml(e.id)}</td>
        <td class="text-muted small">${e.website ? `<a href="${escapeHtml(e.website)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.website)}</a>` : '<span class="text-muted">—</span>'}</td>
        <td class="fw-semibold">${escapeHtml(e.username)}</td>
        <td class="font-monospace"><span class="pw-mask" data-pw="${escapeHtml(e.password)}" title="Hover to reveal · Click to copy">••••••••</span></td>
        <td class="text-muted small text-nowrap">${escapeHtml(formatDate(e.created_at))}</td>
        <td><button class="btn btn-sm btn-outline-danger btn-delete" data-id="${escapeHtml(e.id)}" data-username="${escapeHtml(e.username)}" data-website="${escapeHtml(e.website || '')}" title="Delete entry"><i class="bi bi-trash3"></i></button></td>
      </tr>`).join('');

    entriesArea.innerHTML = `
      <div class="table-responsive">
        <table class="table table-hover table-sm align-middle mb-0">
          <thead class="table-light">
            <tr><th>#</th><th>Website</th><th>Username</th><th>Password</th><th>Saved</th><th></th></tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch (err) {
    entriesArea.innerHTML = `<p class="text-danger text-center mb-0">Failed to load: ${escapeHtml(err.message)}</p>`;
  }
}

btnGenerate.addEventListener('click', () => {
  const pw = generatePassword();
  passwordInput.value = pw;
  passwordInput.removeAttribute('readonly');
  btnCopy.disabled = false;
  updateStrengthUI(pw);
});

passwordInput.addEventListener('input', () => updateStrengthUI(passwordInput.value));

btnCopy.addEventListener('click', async () => {
  if (!passwordInput.value) return;
  try {
    await copyToClipboard(passwordInput.value);
    btnCopy.innerHTML = '<i class="bi bi-clipboard-check me-1"></i> Copied!';
    btnCopy.classList.add('copied');
    if (typeof bootstrap !== 'undefined') {
      new bootstrap.Toast(document.getElementById('copy-toast')).show();
    }
    setTimeout(() => {
      btnCopy.innerHTML = '<i class="bi bi-clipboard me-1"></i> Copy';
      btnCopy.classList.remove('copied');
    }, 2000);
  } catch {
    showAlert('Could not copy to clipboard. Please copy manually.', 'warning');
  }
});

btnRefresh.addEventListener('click', loadEntries);

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert();

  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }

  const website  = websiteInput.value.trim();
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!password) {
    showAlert('Please generate or enter a password before saving.');
    return;
  }

  btnSubmit.disabled = true;
  btnSpinner.classList.remove('d-none');

  try {
    const res = await authFetch(API_BASE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ website, username, password }),
    });
    if (res.status === 401) { handleUnauthorized(); return; }
    const data = await res.json();

    if (res.status === 201) {
      showAlert(`Entry for "${escapeHtml(username)}" saved successfully.`, 'success');
      form.reset();
      form.classList.remove('was-validated');
      passwordInput.setAttribute('readonly', true);
      btnCopy.innerHTML = '<i class="bi bi-clipboard me-1"></i> Copy';
      btnCopy.classList.remove('copied');
      btnCopy.disabled = true;
      updateStrengthUI('');
      loadEntries();
    } else if (res.status === 422 && data.errors) {
      showAlert('Validation error: ' + data.errors.map(e => escapeHtml(e.msg)).join(' | '));
    } else {
      showAlert(data.error || 'An unexpected error occurred.');
    }
  } catch (err) {
    showAlert(`Network error: ${escapeHtml(err.message)}`);
  } finally {
    btnSubmit.disabled = false;
    btnSpinner.classList.add('d-none');
  }
});

// Hover to reveal saved password
entriesArea.addEventListener('mouseover', e => {
  const span = e.target.closest('.pw-mask');
  if (span) span.textContent = span.dataset.pw;
});

entriesArea.addEventListener('mouseout', e => {
  const span = e.target.closest('.pw-mask');
  if (span && !span.contains(e.relatedTarget)) span.textContent = '••••••••';
});

// Click to copy saved password
entriesArea.addEventListener('click', async e => {
  const span = e.target.closest('.pw-mask');
  if (!span) return;
  try {
    await copyToClipboard(span.dataset.pw);
    span.classList.add('pw-copied');
    if (typeof bootstrap !== 'undefined') {
      new bootstrap.Toast(document.getElementById('copy-toast')).show();
    }
    setTimeout(() => span.classList.remove('pw-copied'), 2000);
  } catch {
    if (typeof bootstrap !== 'undefined') {
      const toastEl = document.getElementById('copy-toast');
      toastEl.querySelector('.toast-body').textContent = 'Could not copy — please copy manually.';
      new bootstrap.Toast(toastEl).show();
      setTimeout(() => { toastEl.querySelector('.toast-body').textContent = 'Password copied to clipboard.'; }, 2500);
    }
  }
});

// Delete button — open confirmation modal
let deleteModal = null;
let pendingDeleteId = null;

entriesArea.addEventListener('click', e => {
  const btn = e.target.closest('.btn-delete');
  if (!btn) return;
  pendingDeleteId = btn.dataset.id;
  deleteUsernameEl.textContent = btn.dataset.username;
  if (btn.dataset.website) {
    deleteWebsiteEl.textContent = btn.dataset.website;
    deleteWebsiteWrapEl.classList.remove('d-none');
  } else {
    deleteWebsiteWrapEl.classList.add('d-none');
  }
  deleteErrorEl.classList.add('d-none');
  deleteErrorEl.textContent = '';
  if (!deleteModal) deleteModal = new bootstrap.Modal(deleteModalEl);
  deleteModal.show();
});

btnConfirmDelete.addEventListener('click', async () => {
  if (!pendingDeleteId) return;
  deleteErrorEl.classList.add('d-none');
  btnConfirmDelete.disabled = true;
  deleteSpinnerEl.classList.remove('d-none');

  try {
    const res = await authFetch(`${API_BASE}/${pendingDeleteId}`, { method: 'DELETE' });
    if (res.status === 401) { handleUnauthorized(); return; }
    const data = await res.json();
    if (res.ok) {
      deleteModal.hide();
      loadEntries();
    } else {
      deleteErrorEl.textContent = data.error || 'Failed to delete entry.';
      deleteErrorEl.classList.remove('d-none');
    }
  } catch (err) {
    deleteErrorEl.textContent = `Network error: ${err.message}`;
    deleteErrorEl.classList.remove('d-none');
  } finally {
    btnConfirmDelete.disabled = false;
    deleteSpinnerEl.classList.add('d-none');
  }
});

loadEntries();
