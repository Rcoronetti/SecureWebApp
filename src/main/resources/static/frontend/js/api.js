const API_BASE_URL = '/api';

async function apiCall(endpoint, method = 'GET', body = null, token = null) {
    const headers = {
        'Content-Type': 'application/json'
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : null
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
}

const api = {
    login: (username, password) => apiCall('/auth/login', 'POST', { username, password }),
    register: (username, email, password) => apiCall('/auth/register', 'POST', { username, email, password }),
    getUserInfo: (token) => apiCall('/user/info', 'GET', null, token)
};