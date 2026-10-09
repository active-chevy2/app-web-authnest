const API_BASE = '';
let currentUser = null;
let currentToken = null;

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
	await loadSettings();
	await checkAuth();
	setupEventListeners();
});

async function checkAuth() {
	const token = localStorage.getItem('token');
	if (token) {
		currentToken = token;
		try {
			const response = await fetch(`${API_BASE}/api/user`, {
				headers: { 'Authorization': `Bearer ${token}` }
			});
			if (response.ok) {
				currentUser = await response.json();
				showDashboard();
				return;
			}
		} catch (err) {
			console.error('Auth check failed:', err);
		}
		localStorage.removeItem('token');
	}
	showAuthScreen();
}

async function loadSettings() {
	try {
		const response = await fetch(`${API_BASE}/api/settings`);
		const settings = await response.json();
		document.getElementById('app-title').textContent = settings.AppName || 'Auth App';
		document.getElementById('app-name').textContent = settings.AppName || 'Auth App';
		document.getElementById('app-icon').textContent = settings.AppIcon || '🔐';
	} catch (err) {
		console.error('Failed to load settings:', err);
	}
}

function setupEventListeners() {
	// Auth forms
	document.getElementById('registerForm').addEventListener('submit', handleRegister);
	document.getElementById('loginForm').addEventListener('submit', handleLogin);
	document.getElementById('passwordForm').addEventListener('submit', handleChangePassword);
	document.getElementById('settingsForm').addEventListener('submit', handleUpdateSettings);

	// Navigation
	document.getElementById('navDashboard').addEventListener('click', () => showDashboard());
	document.getElementById('navSettings').addEventListener('click', () => showAdminPanel());
	document.getElementById('navLogout').addEventListener('click', logout);

	// Show login form by default
	switchAuthForm(true);
}

function switchAuthForm(showLogin) {
	const loginForm = document.getElementById('loginForm');
	const registerForm = document.getElementById('registerForm');
	document.getElementById('auth-title').textContent = showLogin ? 'Login' : 'Create Account';

	if (showLogin) {
		loginForm.style.display = 'flex';
		registerForm.style.display = 'none';
	} else {
		loginForm.style.display = 'none';
		registerForm.style.display = 'flex';
	}
}

async function handleRegister(e) {
	e.preventDefault();
	const email = document.getElementById('registerEmail').value;
	const password = document.getElementById('registerPassword').value;
	const confirm = document.getElementById('registerConfirm').value;

	if (password !== confirm) {
		showToast('Passwords do not match', 'error');
		return;
	}

	try {
		const response = await fetch(`${API_BASE}/api/auth/register`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, password })
		});

		const data = await response.json();
		if (response.ok) {
			showToast('Registration successful. Please login.', 'success');
			switchAuthForm(true);
			document.getElementById('registerForm').reset();
		} else {
			showToast(data.error || 'Registration failed', 'error');
		}
	} catch (err) {
		showToast('Registration error: ' + err.message, 'error');
	}
}

async function handleLogin(e) {
	e.preventDefault();
	const email = document.getElementById('loginEmail').value;
	const password = document.getElementById('loginPassword').value;
	const totpCode = document.getElementById('loginTOTP').value;

	try {
		const response = await fetch(`${API_BASE}/api/auth/login`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, password, totp_code: totpCode })
		});

		if (response.status === 202) {
			// 2FA required
			document.getElementById('totpLoginGroup').style.display = 'block';
			showToast('2FA code required', 'error');
			return;
		}

		const data = await response.json();
		if (response.ok) {
			localStorage.setItem('token', data.token);
			currentToken = data.token;
			showToast('Login successful', 'success');
			await checkAuth();
		} else {
			showToast(data.error || 'Login failed', 'error');
		}
	} catch (err) {
		showToast('Login error: ' + err.message, 'error');
	}
}

async function handleChangePassword(e) {
	e.preventDefault();
	const oldPassword = document.getElementById('oldPassword').value;
	const newPassword = document.getElementById('newPassword').value;
	const confirmPassword = document.getElementById('confirmPassword').value;

	if (newPassword !== confirmPassword) {
		showToast('New passwords do not match', 'error');
		return;
	}

	try {
		const response = await fetch(`${API_BASE}/api/user/password`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${currentToken}`
			},
			body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
		});

		const data = await response.json();
		if (response.ok) {
			showToast('Password updated successfully', 'success');
			document.getElementById('passwordForm').reset();
		} else {
			showToast(data.error || 'Failed to update password', 'error');
		}
	} catch (err) {
		showToast('Error: ' + err.message, 'error');
	}
}

async function enable2FA() {
	try {
		const response = await fetch(`${API_BASE}/api/auth/enable-2fa`, {
			method: 'POST',
			headers: { 'Authorization': `Bearer ${currentToken}` }
		});

		const data = await response.json();
		showSetup2FAScreen(data);
	} catch (err) {
		showToast('Failed to enable 2FA: ' + err.message, 'error');
	}
}

function showSetup2FAScreen(data) {
	// Generate QR code URL (simple approach using otpauth)
	const qrUrl = data.qr;
	const qrContainer = document.getElementById('qrCodeContainer');
	
	// Use QR code API
	const qrImage = document.createElement('img');
	qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=${encodeURIComponent(qrUrl)}`;
	qrContainer.innerHTML = '';
	qrContainer.appendChild(qrImage);

	// Store secret for confirmation
	window.tempSecret = data.secret;
	document.getElementById('setup2FAScreen').style.display = 'flex';
}

async function confirmEnable2FA() {
	const code = document.getElementById('confirmTOTP').value;
	if (!code || code.length !== 6) {
		showToast('Please enter a valid 6-digit code', 'error');
		return;
	}

	try {
		const response = await fetch(`${API_BASE}/api/auth/verify-2fa`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${currentToken}`
			},
			body: JSON.stringify({ email: currentUser.email, totp_code: code })
		});

		if (response.ok) {
			currentUser.two_fa_enabled = true;
			showToast('2FA enabled successfully', 'success');
			cancelSetup2FA();
			update2FAStatus();
		} else {
			showToast('Invalid code', 'error');
		}
	} catch (err) {
		showToast('Error: ' + err.message, 'error');
	}
}

function cancelSetup2FA() {
	document.getElementById('setup2FAScreen').style.display = 'none';
	document.getElementById('confirmTOTP').value = '';
}

async function disable2FA() {
	if (!confirm('Are you sure? This will disable 2FA on your account.')) return;

	const code = prompt('Enter your 6-digit code to confirm:');
	if (!code || code.length !== 6) {
		showToast('Invalid code', 'error');
		return;
	}

	try {
		const response = await fetch(`${API_BASE}/api/auth/disable-2fa`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${currentToken}`
			},
			body: JSON.stringify({ totp_code: code })
		});

		const data = await response.json();
		if (response.ok) {
			currentUser.two_fa_enabled = false;
			showToast('2FA disabled', 'success');
			update2FAStatus();
		} else {
			showToast(data.error || 'Failed to disable 2FA', 'error');
		}
	} catch (err) {
		showToast('Error: ' + err.message, 'error');
	}
}

async function export2FA() {
	try {
		const response = await fetch(`${API_BASE}/api/auth/export-2fa`, {
			headers: { 'Authorization': `Bearer ${currentToken}` }
		});

		const data = await response.json();
		const json = JSON.stringify([data], null, 2);
		downloadFile(json, `2fa-export-${new Date().toISOString().split('T')[0]}.json`);
		showToast('2FA exported successfully', 'success');
	} catch (err) {
		showToast('Export failed: ' + err.message, 'error');
	}
}

function downloadFile(content, filename) {
	const blob = new Blob([content], { type: 'application/json' });
	const url = URL.createObjectURL(blob);
	const a = document.createElement('a');
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}

function update2FAStatus() {
	const statusDiv = document.getElementById('twoFAStatus');
	if (currentUser.two_fa_enabled) {
		statusDiv.innerHTML = `
			<p style="margin-bottom: 1rem;">✓ Two-Factor Authentication is <strong>enabled</strong></p>
			<button class="button-secondary" onclick="export2FA()">Export 2FA Backup</button>
			<button class="button-secondary" style="margin-left: 0.5rem;" onclick="disable2FA()">Disable 2FA</button>
		`;
	} else {
		statusDiv.innerHTML = `
			<p style="margin-bottom: 1rem;">Two-Factor Authentication is <strong>disabled</strong></p>
			<button class="button-primary" onclick="enable2FA()">Enable 2FA</button>
		`;
	}
}

async function handleUpdateSettings(e) {
	e.preventDefault();
	const settings = {
		AppName: document.getElementById('appName').value,
		AppDescription: document.getElementById('appDescription').value,
		AppIcon: document.getElementById('appIcon').value,
		PublicSignup: document.getElementById('publicSignup').checked
	};

	try {
		const response = await fetch(`${API_BASE}/api/settings`, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${currentToken}`
			},
			body: JSON.stringify(settings)
		});

		const data = await response.json();
		if (response.ok) {
			showToast('Settings updated', 'success');
			await loadSettings();
		} else {
			showToast(data.error || 'Failed to update settings', 'error');
		}
	} catch (err) {
		showToast('Error: ' + err.message, 'error');
	}
}

async function loadAdminPanel() {
	if (!currentUser || !currentUser.is_admin) return;

	// Load settings
	try {
		const response = await fetch(`${API_BASE}/api/settings`);
		const settings = await response.json();
		document.getElementById('appName').value = settings.AppName || '';
		document.getElementById('appIcon').value = settings.AppIcon || '';
		document.getElementById('appDescription').value = settings.AppDescription || '';
		document.getElementById('publicSignup').checked = settings.PublicSignup || false;
	} catch (err) {
		console.error('Failed to load settings:', err);
	}

	// Load users
	try {
		const response = await fetch(`${API_BASE}/api/users`, {
			headers: { 'Authorization': `Bearer ${currentToken}` }
		});
		const users = await response.json();
		displayUsers(users);
	} catch (err) {
		showToast('Failed to load users: ' + err.message, 'error');
	}
}

function displayUsers(users) {
	const usersList = document.getElementById('usersList');
	let html = '<table><thead><tr><th>Email</th><th>2FA</th><th>Admin</th><th>Created</th><th>Action</th></tr></thead><tbody>';

	users.forEach(user => {
		const twoFA = user.two_fa_enabled ? '✓' : '✗';
		const admin = user.is_admin ? '✓' : '✗';
		const created = new Date(user.created_at).toLocaleDateString();

		html += `<tr>
			<td>${user.email}</td>
			<td>${twoFA}</td>
			<td>${admin}</td>
			<td>${created}</td>
			<td>
				${user.id !== currentUser.id ? `<button class="delete-btn" onclick="deleteUser('${user.id}')">Delete</button>` : '—'}
			</td>
		</tr>`;
	});

	html += '</tbody></table>';
	usersList.innerHTML = html;
}

async function deleteUser(userId) {
	if (!confirm('Delete this user permanently?')) return;

	try {
		const response = await fetch(`${API_BASE}/api/users/${userId}`, {
			method: 'DELETE',
			headers: { 'Authorization': `Bearer ${currentToken}` }
		});

		if (response.ok) {
			showToast('User deleted', 'success');
			await loadAdminPanel();
		} else {
			showToast('Failed to delete user', 'error');
		}
	} catch (err) {
		showToast('Error: ' + err.message, 'error');
	}
}

function showDashboard() {
	document.getElementById('authScreen').classList.remove('active');
	document.getElementById('dashboardScreen').classList.add('active');
	document.getElementById('setup2FAScreen').style.display = 'none';
	document.getElementById('navDashboard').style.display = 'block';
	document.getElementById('navLogout').style.display = 'block';

	if (currentUser && currentUser.is_admin) {
		document.getElementById('adminPanel').style.display = 'block';
		document.getElementById('navSettings').style.display = 'block';
		loadAdminPanel();
	}

	// Update user info
	document.getElementById('userEmail').textContent = currentUser.email;
	document.getElementById('userCreated').textContent = new Date(currentUser.created_at).toLocaleDateString();
	document.getElementById('userLastLogin').textContent = currentUser.last_login_at
		? new Date(currentUser.last_login_at).toLocaleDateString()
		: 'Never';

	update2FAStatus();
}

function showAuthScreen() {
	document.getElementById('authScreen').classList.add('active');
	document.getElementById('dashboardScreen').classList.remove('active');
	document.getElementById('navDashboard').style.display = 'none';
	document.getElementById('navSettings').style.display = 'none';
	document.getElementById('navLogout').style.display = 'none';
}

function showAdminPanel() {
	loadAdminPanel();
	document.getElementById('adminPanel').scrollIntoView({ behaviour: 'smooth' });
}

function logout() {
	localStorage.removeItem('token');
	currentUser = null;
	currentToken = null;
	showAuthScreen();
	document.getElementById('loginForm').reset();
	document.getElementById('registerForm').reset();
	showToast('Logged out', 'success');
}

function showToast(message, type = 'info') {
	const toast = document.getElementById('toast');
	toast.textContent = message;
	toast.className = 'toast visible ' + type;

	setTimeout(() => {
		toast.classList.remove('visible');
	}, 3000);
}
