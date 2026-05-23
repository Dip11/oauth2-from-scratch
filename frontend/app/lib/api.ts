/**
 * fetch wrapper that transparently refreshes the access token on 401.
 *
 * Flow:
 *   1. Call the URL.
 *   2. If 401, POST /auth/refresh once.
 *   3. If refresh succeeds, retry the original call. Return that response.
 *   4. If refresh also fails (or already retried), return the 401 so the
 *      caller can redirect to /login.
 *
 * The browser handles the actual cookies; we never read or write them here.
 */

const apiUrl = process.env.NEXT_PUBLIC_API_URL!;

// Coalesce concurrent refresh attempts. If five requests all see 401 at the
// same time, we only want ONE /auth/refresh call to actually happen.
let inflightRefresh: Promise<boolean> | null = null;

async function refreshOnce(): Promise<boolean> {
  if (!inflightRefresh) {
    inflightRefresh = fetch(`${apiUrl}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        // Clear so future expirations can refresh again later.
        inflightRefresh = null;
      });
  }
  return inflightRefresh;
}

export async function apiFetch(
  input: string,
  init: RequestInit = {},
): Promise<Response> {
  const url = input.startsWith('http') ? input : `${apiUrl}${input}`;
  const opts: RequestInit = { ...init, credentials: 'include' };

  const first = await fetch(url, opts);
  if (first.status !== 401) return first;

  const refreshed = await refreshOnce();
  if (!refreshed) return first; // surface the original 401

  return fetch(url, opts); // retry once with the new cookies
}
