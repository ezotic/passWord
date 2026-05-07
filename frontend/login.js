'use strict';

// If already logged in, go straight to the app
if (localStorage.getItem('auth_token')) {
  window.location.replace('index.html');
}

// Show "password changed" banner when redirected back from change-password page
if (new URLSearchParams(window.location.search).get('changed') === '1') {
  document.addEventListener('DOMContentLoaded', () => {
    const area = document.getElementById('login-alert');
    if (area) {
      area.innerHTML = `
        <div class="alert alert-success alert-dismissible fade show" role="alert">
          Password changed successfully. Please log in with your new password.
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>`;
    }
  });
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showAlert(areaId, message, type) {
  document.getElementById(areaId).innerHTML = `
    <div class="alert alert-${type || 'danger'} alert-dismissible fade show" role="alert">
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>`;
}

function clearAlert(areaId) {
  document.getElementById(areaId).innerHTML = '';
}

function setLoading(btnId, spinnerId, isLoading) {
  document.getElementById(btnId).disabled = isLoading;
  document.getElementById(spinnerId).classList.toggle('d-none', !isLoading);
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

// ── Wire password toggles ─────────────────────────────────────────────────────

wireToggle('login-toggle-pw', 'login-password');
wireToggle('reg-toggle-pw',   'reg-password');

// ── Login form ────────────────────────────────────────────────────────────────

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert('login-alert');

  const form     = e.currentTarget;
  const username = form.username.value.trim();
  const password = form.password.value;

  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }

  setLoading('btn-login', 'login-spinner', true);

  try {
    const res  = await fetch('/api/auth/login', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.ok) {
      localStorage.setItem('auth_token',    data.token);
      localStorage.setItem('auth_username', data.username);
      localStorage.setItem('auth_isAdmin',  String(data.isAdmin === true));
      // Force password change before entering the app
      if (data.mustChangePassword) {
        window.location.replace('change-password.html');
      } else {
        window.location.replace('index.html');
      }
    } else if (res.status === 429) {
      showAlert('login-alert', 'Too many login attempts. Please wait 15 minutes and try again.');
    } else {
      showAlert('login-alert', escapeHtml(data.error || 'Login failed.'));
    }
  } catch (err) {
    showAlert('login-alert', `Network error: ${escapeHtml(err.message)}`);
  } finally {
    setLoading('btn-login', 'login-spinner', false);
  }
});

// ── Register form ─────────────────────────────────────────────────────────────

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearAlert('register-alert');

  const form     = e.currentTarget;
  const username = form.username.value.trim();
  const password = form.password.value;
  const confirm  = form.confirm.value;

  const confirmInput    = document.getElementById('reg-confirm');
  const confirmFeedback = document.getElementById('reg-confirm-feedback');
  if (password !== confirm) {
    confirmInput.classList.add('is-invalid');
    confirmFeedback.textContent = 'Passwords do not match.';
    return;
  }
  confirmInput.classList.remove('is-invalid');

  if (!form.checkValidity()) {
    form.classList.add('was-validated');
    return;
  }

  setLoading('btn-register', 'register-spinner', true);

  try {
    const res  = await fetch('/api/auth/register', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (res.status === 201) {
      // Auto-login with the just-registered credentials
      try {
        const loginRes  = await fetch('/api/auth/login', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ username, password }),
        });
        const loginData = await loginRes.json();
        if (loginRes.ok) {
          localStorage.setItem('auth_token',    loginData.token);
          localStorage.setItem('auth_username', loginData.username);
          localStorage.setItem('auth_isAdmin',  String(loginData.isAdmin === true));
          window.location.replace(loginData.mustChangePassword ? 'change-password.html' : 'index.html');
          return;
        }
      } catch { /* fall through to manual login */ }
      // Fallback: switch to login tab if auto-login failed
      showAlert('register-alert', 'Account created. Please log in.', 'success');
      form.reset();
      form.classList.remove('was-validated');
      bootstrap.Tab.getOrCreateInstance(document.getElementById('tab-login-btn')).show();
      document.getElementById('login-username').value = username;
    } else if (res.status === 409) {
      showAlert('register-alert', 'That username is already taken. Please choose another.');
    } else if (res.status === 422 && data.errors) {
      showAlert('register-alert', data.errors.map(e => escapeHtml(e.msg)).join('<br>'));
    } else if (res.status === 429) {
      showAlert('register-alert', 'Too many requests. Please try again later.');
    } else {
      showAlert('register-alert', escapeHtml(data.error || 'Registration failed.'));
    }
  } catch (err) {
    showAlert('register-alert', `Network error: ${escapeHtml(err.message)}`);
  } finally {
    setLoading('btn-register', 'register-spinner', false);
  }
});
