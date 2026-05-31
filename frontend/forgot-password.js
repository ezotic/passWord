'use strict';

if (localStorage.getItem('auth_token')) {
  window.location.replace('index.html');
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showAlert(message, type) {
  document.getElementById('reset-alert').innerHTML = `
    <div class="alert alert-${type || 'danger'} alert-dismissible fade show" role="alert">
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`;
}

function clearAlert() {
  document.getElementById('reset-alert').innerHTML = '';
}

// ── Password toggle ───────────────────────────────────────────────────────────

document.getElementById('toggle-new').addEventListener('click', () => {
  const input = document.getElementById('new-password');
  const icon  = document.querySelector('#toggle-new i');
  if (input.type === 'password') {
    input.type = 'text';
    icon.className = 'bi bi-eye-slash';
  } else {
    input.type = 'password';
    icon.className = 'bi bi-eye';
  }
});

// ── Live confirm-match indicator ──────────────────────────────────────────────

const confirmInput     = document.getElementById('confirm-password');
const newPasswordInput = document.getElementById('new-password');

function updateConfirmValidity() {
  if (!confirmInput.value) {
    confirmInput.classList.remove('is-invalid', 'is-valid');
    return;
  }
  const matches = confirmInput.value === newPasswordInput.value;
  confirmInput.classList.toggle('is-invalid', !matches);
  confirmInput.classList.toggle('is-valid',    matches);
}

confirmInput.addEventListener('input',     updateConfirmValidity);
newPasswordInput.addEventListener('input', updateConfirmValidity);

// ── Form submit ───────────────────────────────────────────────────────────────

document.getElementById('reset-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert();

  const form        = e.currentTarget;
  const username    = form.username.value.trim();
  const newPassword = form.password.value;
  const confirm     = form.confirm.value;

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

  const btn     = document.getElementById('btn-reset');
  const spinner = document.getElementById('reset-spinner');
  btn.disabled  = true;
  spinner.classList.remove('d-none');

  try {
    const res  = await fetch('/api/auth/reset-password', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password: newPassword }),
    });
    const data = await res.json();

    if (res.ok) {
      window.location.replace('login.html?reset=1');
    } else if (res.status === 404) {
      showAlert('Username not found. Please check and try again.');
    } else if (res.status === 422 && data.errors) {
      showAlert(data.errors.map(e => escapeHtml(e.msg)).join('<br>'));
    } else if (res.status === 429) {
      showAlert('Too many reset attempts. Please wait 15 minutes and try again.');
    } else {
      showAlert(escapeHtml(data.error || 'Reset failed. Please try again.'));
    }
  } catch (err) {
    showAlert(`Network error: ${escapeHtml(err.message)}`);
  } finally {
    btn.disabled = false;
    spinner.classList.add('d-none');
  }
});
