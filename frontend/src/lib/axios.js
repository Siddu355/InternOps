```javascript
import axios from 'axios';

import { toast } from 'sonner';
import { captureException } from './sentry';
import { getApiErrorInfo, getApiErrorMessage } from './apiError';

// ---------------------------------------------------------------------------
// API BASE URL
// ---------------------------------------------------------------------------

export function getBaseUrl() {
  const raw = import.meta.env.VITE_API_URL;

  if (!raw) {
    return '/api/v1';
  }

  let url = raw.trim();

  if (!/^https?:\/\//i.test(url)) {
    console.warn(
      `[api] VITE_API_URL "${raw}" has no protocol; defaulting to http://`
    );

    url = `http://${url}`;
  }

  url = url.replace(/\/+$/, '');

  const hasApiVersionPath = /\/api\/v\d+(?:\/|$)/i.test(url);
  const hasApiOnlyPath = /\/api$/i.test(url);

  if (!hasApiVersionPath) {
    if (hasApiOnlyPath) {
      url = url.replace(/\/api$/i, '/api/v1');
    } else {
      url = `${url}/api/v1`;
    }
  }

  return url;
}

// ---------------------------------------------------------------------------
// AXIOS INSTANCE
// ---------------------------------------------------------------------------

const api = axios.create({
  baseURL: getBaseUrl(),
  withCredentials: true,
  timeout: 15000,
});

// ---------------------------------------------------------------------------
// GLOBAL ERROR TOAST
// ---------------------------------------------------------------------------

function shouldShowGlobalToast(err) {
  const original = err?.config || {};
  const url = original.url || '';

  const isAuthRoute =
    url.includes('/auth/login') ||
    url.includes('/auth/refresh') ||
    url.includes('/auth/register');

  return !(
    original._retry ||
    original._suppressGlobalError ||
    isAuthRoute ||
    url.includes('/auth/refresh')
  );
}

// ---------------------------------------------------------------------------
// AI CHAT ERROR HANDLING
// ---------------------------------------------------------------------------

export function getAiChatErrorMessage(err) {
  if (!err?.response) {
    if (err?.code === 'ECONNABORTED') {
      return {
        message:
          'The AI assistant took too long to respond. Please try again.',
        retryable: true,
      };
    }

    return {
      message:
        'Unable to reach the AI assistant. Check your connection and try again.',
      retryable: true,
    };
  }

  const status = err.response.status;
  const responseData = err.response.data;

  if (status === 401 || status === 403) {
    return {
      message: "You don't have access to the AI assistant right now.",
      retryable: false,
    };
  }

  if (status === 429) {
    const hasServerMessage = Boolean(
      responseData &&
        (
          responseData.error ||
          responseData.message ||
          responseData.detail ||
          responseData.description ||
          responseData.details?.length ||
          responseData.errors?.length
        )
    );

    return {
      message: hasServerMessage
        ? getApiErrorMessage(err)
        : "You've reached the AI assistant's usage limit. Please try again later.",
      retryable: false,
    };
  }

  if (status >= 500) {
    return {
      message:
        'The AI assistant is temporarily unavailable. Please try again in a moment.',
      retryable: true,
    };
  }

  const serverMessage = getApiErrorMessage(err);

  return {
    message:
      serverMessage || 'Could not process that request. Please try rephrasing.',
    retryable: false,
  };
}

// ---------------------------------------------------------------------------
// GLOBAL API ERROR
// ---------------------------------------------------------------------------

function notifyGlobalApiError(err) {
  if (!shouldShowGlobalToast(err)) {
    return;
  }

  if (!err?.response) {
    const networkMessage =
      err?.code === 'ECONNABORTED'
        ? 'The request timed out. Please check your connection and try again.'
        : 'Unable to connect to the server. Check your connection and try again.';

    toast.error(networkMessage);
    return;
  }

  const status = err.response.status;
  const serverMessage = getApiErrorMessage(err);

  const message =
    status >= 500
      ? 'Something went wrong on our side. Please try again later.'
      : serverMessage ||
        'Request failed. Please check your input and try again.';

  toast.error(message);
}

// ---------------------------------------------------------------------------
// CSRF PROTECTION
// ---------------------------------------------------------------------------

let csrfToken = null;
let csrfPromise = null;
let csrfGeneration = 0;

const CSRF_EXEMPT_PATHS = [
  '/auth/login',
  '/auth/refresh',
  '/auth/logout',
  '/auth/forgot-password',
  '/auth/reset-password',
  '/client-error',
];

function isCsrfExempt(url) {
  return Boolean(
    url && CSRF_EXEMPT_PATHS.some((path) => url.includes(path))
  );
}

// IMPORTANT:
// auth.js imports this function:
//
// import { clearCsrfToken, registerAuthStore } from '../lib/axios';
//
// Therefore it MUST be a named export.

export function clearCsrfToken() {
  csrfGeneration += 1;
  csrfToken = null;
  csrfPromise = null;
}

async function getCsrfToken() {
  if (csrfToken) {
    return csrfToken;
  }

  if (csrfPromise) {
    return csrfPromise;
  }

  const generation = csrfGeneration;

  csrfPromise = api
    .get('/auth/csrf-token', {
      _suppressGlobalError: true,
    })
    .then((res) => {
      if (generation !== csrfGeneration) {
        throw new Error('Discarding stale CSRF token');
      }

      const token = res.data?.csrfToken;

      if (!token) {
        throw new Error('CSRF token was not returned by the server');
      }

      csrfToken = token;

      return csrfToken;
    })
    .finally(() => {
      csrfPromise = null;
    });

  return csrfPromise;
}

// ---------------------------------------------------------------------------
// LEGACY AUTH STORAGE CLEANUP
// ---------------------------------------------------------------------------

function removeLegacyAuthStorage() {
  try {
    if (typeof window === 'undefined') {
      return;
    }

    window.localStorage.removeItem('user');
  } catch {
    // Ignore localStorage errors.
  }
}

// ---------------------------------------------------------------------------
// AUTH STORE BRIDGE
// ---------------------------------------------------------------------------

let _authStore = null;

export function registerAuthStore(store) {
  _authStore = store;
}

function getMemoryAccessToken() {
  return _authStore?.getState?.()?.accessToken || null;
}

// ---------------------------------------------------------------------------
// REFRESH TOKEN ROTATION
// ---------------------------------------------------------------------------

let sharedRefreshPromise = null;

async function performRefresh() {
  const generation =
    _authStore?.getState?.()?.authGeneration ?? 0;

  try {
    const response = await api.post(
      '/auth/refresh',
      {},
      {
        _isRefreshRequest: true,
        _suppressGlobalError: true,
      }
    );

    const accessToken = response.data?.accessToken;
    const refreshedUser = response.data?.user;

    if (!accessToken) {
      throw new Error(
        'Refresh response did not contain an access token'
      );
    }

    const currentUser =
      _authStore?.getState?.()?.user || null;

    const user = refreshedUser || currentUser;

    if (_authStore) {
      _authStore.getState().setAuth({
        accessToken,
        user,
      });
    }

    clearCsrfToken();
    removeLegacyAuthStorage();

    return {
      accessToken,
      user,
    };
  } catch (error) {
    const current = _authStore?.getState?.();

    if (current && current.authGeneration === generation) {
      current.logout();

      clearCsrfToken();
      removeLegacyAuthStorage();

      if (typeof window !== 'undefined') {
        window.dispatchEvent(new Event('auth:logout'));
      }
    }

    throw error;
  }
}

export function refreshSession() {
  if (sharedRefreshPromise) {
    return sharedRefreshPromise;
  }

  const execute = () => performRefresh();

  const coordinated =
    typeof navigator !== 'undefined' &&
    navigator.locks?.request
      ? navigator.locks.request(
          'internops-refresh-token',
          {
            mode: 'exclusive',
          },
          execute
        )
      : execute();

  sharedRefreshPromise = Promise.resolve(
    coordinated
  ).finally(() => {
    sharedRefreshPromise = null;
  });

  return sharedRefreshPromise;
}

// ---------------------------------------------------------------------------
// REQUEST INTERCEPTOR
// ---------------------------------------------------------------------------

api.interceptors.request.use(
  async (config) => {
    const token = getMemoryAccessToken();

    // Add access token.
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }

    const method = (
      config.method || 'get'
    ).toLowerCase();

    const isUnsafeMethod = ![
      'get',
      'head',
      'options',
    ].includes(method);

    // Add CSRF token to unsafe requests.
    if (
      isUnsafeMethod &&
      !isCsrfExempt(config.url)
    ) {
      try {
        config.headers = config.headers || {};

        config.headers['X-CSRF-Token'] =
          await getCsrfToken();
      } catch {
        return Promise.reject(
          new Error(
            'CSRF token unavailable; refusing unsafe request'
          )
        );
      }
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// ---------------------------------------------------------------------------
// RESPONSE INTERCEPTOR
// ---------------------------------------------------------------------------

api.interceptors.response.use(
  // -------------------------------------------------------------------------
  // SUCCESS
  // -------------------------------------------------------------------------

  (response) => {
    const url = response.config?.url || '';

    if (
      url.includes('/auth/login') ||
      url.includes('/auth/logout') ||
      url.includes('/me/revoke-all') ||
      url.includes('/auth/reset-password')
    ) {
      clearCsrfToken();
    }

    return response;
  },

  // -------------------------------------------------------------------------
  // ERROR
  // -------------------------------------------------------------------------

  async (err) => {
    if (axios.isCancel(err)) {
      return Promise.reject(err);
    }

    console.error(
      '[Global API Error]',
      err.response?.data || err.message,
      err.config?.url
    );

    const errorStatus =
      err.response?.status;

    // Send server errors to Sentry.
    if (errorStatus >= 500) {
      captureException(err, {
        tags: {
          source: 'api',
          statusCode: String(errorStatus),
          route: err.config?.url,
        },
        extra: {
          responseData: err.response?.data,
        },
      });
    }

    const original = err.config || {};
    const status = err.response?.status;
    const url = original.url || '';

    const isAuthRoute =
      url.includes('/auth/login') ||
      url.includes('/auth/refresh') ||
      url.includes('/auth/register');

    const hasToken =
      Boolean(getMemoryAccessToken());

    // -----------------------------------------------------------------------
    // CSRF FAILURE -> GET NEW TOKEN -> RETRY
    // -----------------------------------------------------------------------

    if (
      status === 403 &&
      !original._csrfRetry &&
      err.response?.data?.error ===
        'CSRF validation failed'
    ) {
      original._csrfRetry = true;

      clearCsrfToken();

      try {
        original.headers =
          original.headers || {};

        original.headers['X-CSRF-Token'] =
          await getCsrfToken();

        return api(original);
      } catch (csrfError) {
        notifyGlobalApiError(csrfError);

        return Promise.reject(csrfError);
      }
    }

    // -----------------------------------------------------------------------
    // IMPERSONATION
    // -----------------------------------------------------------------------

    if (
      status === 401 &&
      !original._retry &&
      !isAuthRoute &&
      hasToken &&
      _authStore?.getState?.()?.impersonation
    ) {
      original._retry = true;

      try {
        _authStore
          .getState()
          .exitImpersonation();

        const adminToken =
          getMemoryAccessToken();

        if (adminToken) {
          original.headers =
            original.headers || {};

          original.headers.Authorization =
            `Bearer ${adminToken}`;

          return api(original);
        }
      } catch (error) {
        console.error(
          '[Auth] Failed to exit impersonation',
          error
        );
      }
    }

    // -----------------------------------------------------------------------
    // ACCESS TOKEN EXPIRED -> REFRESH -> RETRY
    // -----------------------------------------------------------------------

    if (
      status === 401 &&
      hasToken &&
      !original._retry &&
      !isAuthRoute &&
      !original._isRefreshRequest
    ) {
      original._retry = true;

      try {
        const { accessToken } =
          await refreshSession();

        original.headers =
          original.headers || {};

        original.headers.Authorization =
          `Bearer ${accessToken}`;

        return api(original);
      } catch (refreshError) {
        return Promise.reject(refreshError);
      }
    }

    // -----------------------------------------------------------------------
    // NORMAL API ERROR
    // -----------------------------------------------------------------------

    try {
      const errorInfo =
        getApiErrorInfo(err);

      err.userMessage =
        errorInfo?.message;

      err.errorCode =
        errorInfo?.code;

      err.requestId =
        errorInfo?.requestId;
    } catch {
      // Do not allow error formatting to break
      // the original request error.
    }

    notifyGlobalApiError(err);

    return Promise.reject(err);
  }
);

// ---------------------------------------------------------------------------
// EXPORTS
// ---------------------------------------------------------------------------

export {
  api,
  getApiErrorMessage,
};

export default api;
```
