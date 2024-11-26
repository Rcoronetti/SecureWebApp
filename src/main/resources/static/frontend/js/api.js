const API_BASE_URL = 'http://localhost:8080/api';

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

    const responseData = await response.text();
    let parsedData;
    try {
        parsedData = JSON.parse(responseData);
    } catch (e) {
        parsedData = responseData;
    }

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}, message: ${parsedData}`);
    }

    return parsedData;
}

export const login = (username, password) => apiCall('/auth/login', 'POST', { username, password });
export const register = (username, email, password) => apiCall('/auth/register', 'POST', { username, email, password });
export const getUserInfo = (token) => apiCall('/user/info', 'GET', null, token);