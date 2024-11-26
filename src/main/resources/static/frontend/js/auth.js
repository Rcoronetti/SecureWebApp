import * as api from './api.js';

function setToken(token) {
    localStorage.setItem('token', token);
}

function getToken() {
    return localStorage.getItem('token');
}

function removeToken() {
    localStorage.removeItem('token');
}

async function login(username, password) {
    try {
        const response = await api.login(username, password);
        setToken(response.token);
        window.location.href = 'dashboard.html';
    } catch (error) {
        console.error('Erro no login:', error);
        alert('Falha no login. Verifique suas credenciais.');
    }
}

async function register(username, email, password) {
    try {
        const response = await api.register(username, email, password);
        console.log('Resposta do registro:', response);
        alert('Registro bem-sucedido! Por favor, faça login.');
        window.location.href = 'login.html';
    } catch (error) {
        console.error('Erro no registro:', error);
        alert(`Falha no registro: ${error.message}`);
    }
}

function logout() {
    removeToken();
    window.location.href = 'index.html';
}

async function loadUserInfo() {
    const token = getToken();
    if (!token) {
        window.location.href = 'login.html';
        return;
    }

    try {
        const userInfo = await api.getUserInfo(token);
        document.getElementById('userInfo').innerHTML = `
            <p>Bem-vindo, ${userInfo.username}!</p>
            <p>Email: ${userInfo.email}</p>
        `;
    } catch (error) {
        console.error('Erro ao carregar informações do usuário:', error);
        alert('Falha ao carregar informações do usuário. Por favor, faça login novamente.');
        logout();
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            login(username, password);
        });
    }

    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            register(username, email, password);
        });
    }

    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }

    if (window.location.pathname.endsWith('dashboard.html')) {
        loadUserInfo();
    }
});