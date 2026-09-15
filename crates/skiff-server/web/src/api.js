import { store } from './store';
import { i18n } from './i18n';

export class ApiError extends Error {}

export async function api(method, path, body) {
  let res;
  try {
    res = await fetch(store.base + path, {
      method,
      headers: {
        'X-Admin-Token': store.token,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(i18n.global.t('common.networkError'));
  }
  if (res.status === 401) throw new ApiError(i18n.global.t('common.authFailed'));
  const text = await res.text();
  const contentType = res.headers.get('content-type') || '';
  // Success responses may be plain text ("OK") or JSON; errors are JSON.
  if (!res.ok) {
    let msg = i18n.global.t('common.requestFailed', { status: res.status });
    if (contentType.includes('application/json')) {
      try { msg = JSON.parse(text)?.error || msg; } catch { /* keep default */ }
    }
    throw new ApiError(msg);
  }
  if (contentType.includes('application/json')) {
    try { return JSON.parse(text); } catch { return null; }
  }
  return null;
}

export function fmtTime(ms) {
  if (!ms) return '';
  return new Date(ms).toLocaleString();
}
