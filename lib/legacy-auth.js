const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const { URLSearchParams } = require('url');

/**
 * Perform login to a web app and return auth headers.
 * @param {string} loginUrl - The login endpoint URL.
 * @param {object} credentials - { username: '...', password: '...' }
 * @param {object} extraHeaders - Optional headers to include in login request.
 * @returns {object} - { success, cookies, token, headers }
 */
async function performLogin(loginUrl, credentials = {}, extraHeaders = {}) {
  try {
    const res = await fetch(loginUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...extraHeaders
      },
      body: new URLSearchParams(credentials),
      redirect: 'manual' // so it doesn't follow auto redirects
    });

    const cookieHeader = res.headers.get('set-cookie');
    const bodyText = await res.text();

    const token = bodyText.match(/token=([\w-]+)/)?.[1] || null;

    return {
      success: res.status === 200 || res.status === 302,
      cookies: cookieHeader,
      token,
      headers: {
        ...(cookieHeader && { Cookie: cookieHeader }),
        ...(token && { Authorization: `Bearer ${token}` })
      }
    };
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { performLogin };
