'use strict';

// Must be logged in to reach this page
const _token = localStorage.getItem('auth_token');
if (!_token) {
  window.location.replace('login.html');
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showAlert(message, type) {
  document.getElementById('change-alert').innerHTML = `
    <div class="alert alert-${type || 'danger'} alert-dismissible fade show" role="alert">
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`;
}

function clearAlert() {
  document.getElementById('change-alert').innerHTML = '';
}

function wireToggle(toggleId, inputId) {
  document.getElementById(toggleId).addEventListener('click', () => {
    const input = document.getElementById(inputId);
    const icon  = document.querySelector(`#${toggleId} i`);
    if (input.type === 'password') {
      input.type = 'text';
      icon.className = 'bi bi-eye-slash';
    } else {
      input.type = 'password';
      icon.className = 'bi bi-eye';
    }
  });
}

wireToggle('toggle-current', 'current-password');
wireToggle('toggle-new',     'new-password');

// Live match check — keep confirm field red until passwords match exactly
const confirmInput = document.getElementById('confirm-password');
const newPasswordInput = document.getElementById('new-password');

function updateConfirmValidity() {
  if (!confirmInput.value) {
    confirmInput.classList.remove('is-invalid', 'is-valid');
    return;
  }
  const matches = confirmInput.value === newPasswordInput.value;
  confirmInput.classList.toggle('is-invalid', !matches);
  confirmInput.classList.toggle('is-valid', matches);
}

confirmInput.addEventListener('input', updateConfirmValidity);
newPasswordInput.addEventListener('input', updateConfirmValidity);

// ── Form submit ───────────────────────────────────────────────────────────────

document.getElementById('change-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert();

  const form            = e.currentTarget;
  const currentPassword = form.currentPassword.value;
  const newPassword     = form.password.value;
  const confirm         = form.confirm.value;

  // Client-side confirm check
  const confirmFeedback = document.getElementById('confirm-feedback');
  if (newPassword !== confirm) {
    confirmInput.classList.add('is-invalid');
    confirmFeedback.textContent = 'Passwords do not match.';
    return;
  }
  confirmInput.classList.remove('is-invalid');

  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }

  const btn     = document.getElementById('btn-change');
  const spinner = document.getElementById('change-spinner');
  btn.disabled  = true;
  spinner.classList.remove('d-none');

  try {
    const res  = await fetch('/api/auth/change-password', {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': 'Bearer ' + _token,
      },
      body: JSON.stringify({ currentPassword, password: newPassword }),
    });
    const data = await res.json();

    if (res.ok) {
      // Clear session — user must log in fresh with the new password
      localStorage.removeItem('auth_token');
      localStorage.removeItem('auth_username');
      localStorage.removeItem('auth_isAdmin');
      window.location.replace('login.html?changed=1');
    } else if (res.status === 401) {
      showAlert('Current password is incorrect.');
    } else if (res.status === 422 && data.errors) {
      showAlert(data.errors.map(e => escapeHtml(e.msg)).join('<br>'));
    } else {
      showAlert(escapeHtml(data.error || 'Failed to change password.'));
    }
  } catch (err) {
    showAlert(`Network error: ${escapeHtml(err.message)}`);
  } finally {
    btn.disabled = false;
    spinner.classList.add('d-none');
  }
});
