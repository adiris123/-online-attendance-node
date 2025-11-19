// Shared authentication utilities
(function() {
  'use strict';

  window.getAuth = function() {
    try {
      const raw = localStorage.getItem('auth');
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      console.error('Error parsing auth:', e);
      return null;
    }
  };

  window.authFetch = function(url, options = {}) {
    const auth = getAuth();
    if (!auth || !auth.token || !auth.user) {
      window.location.href = 'index.html';
      throw new Error('Not authenticated');
    }

    const headers = Object.assign({}, options.headers || {}, {
      'x-auth-token': auth.token,
    });

    return fetch(url, Object.assign({}, options, { headers })).then(async (res) => {
      if (res.status === 401) {
        localStorage.removeItem('auth');
        window.location.href = 'index.html';
        throw new Error('Unauthorized');
      }
      if (res.status === 403) {
        const data = await res.json().catch(() => ({}));
        alert(data.error || 'Access denied for this operation.');
        throw new Error('Forbidden');
      }
      return res;
    });
  };

  window.logout = async function() {
    const auth = getAuth();
    if (auth && auth.token) {
      try {
        await authFetch('/api/logout', { method: 'POST' });
      } catch (e) {
        // Ignore errors - clear local storage anyway
        console.error('Logout API error:', e);
      }
    }
    localStorage.removeItem('auth');
    window.location.href = 'index.html';
  };
})();

