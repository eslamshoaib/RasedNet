/** Minimal same-origin JSON client. Adds the CSRF token to every state-changing request. */
import { getLang, t } from "./i18n";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export const UNAUTHORIZED_EVENT = "rasednet:unauthorized";

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

function readCookie(name: string): string | null {
  for (const part of document.cookie.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

export type QueryValue = string | number | boolean | null | undefined;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Record<string, QueryValue>;
}

export function buildUrl(path: string, query?: Record<string, QueryValue>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json", "X-Lang": getLang() };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") {
    const token = csrfToken ?? readCookie("rasednet_csrf");
    if (token) headers["X-CSRF-Token"] = token;
  }
  let response: Response;
  try {
    response = await fetch(buildUrl(path, options.query), {
      method,
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, t("تعذر الاتصال بالخادم. تحقق من تشغيل خدمة راصد", "Cannot reach the server. Check that the RasedNet service is running."));
  }
  if (response.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    const detail = (data as { detail?: unknown } | null)?.detail;
    const message = typeof detail === "string" ? detail : t("حدث خطأ غير متوقع", "An unexpected error occurred");
    if (response.status === 401 && path !== "/api/auth/login") {
      window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    }
    throw new ApiError(response.status, message);
  }
  return data as T;
}

/** GET a URL and save the response as a file (e.g. an Excel/JSON report). */
export async function downloadGet(path: string, filename: string): Promise<void> {
  const response = await fetch(path, { method: "GET", credentials: "same-origin", headers: { "X-Lang": getLang() } });
  if (!response.ok) {
    let message = t("تعذر تنزيل الملف", "Could not download the file");
    try {
      const data = await response.json();
      if (typeof data?.detail === "string") message = data.detail;
    } catch {
      /* not JSON */
    }
    throw new ApiError(response.status, message);
  }
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** POST a JSON body and save the response as a file (e.g. CSV export). */
export async function downloadFile(path: string, body: unknown, filename: string): Promise<void> {
  const token = csrfToken ?? readCookie("rasednet_csrf");
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Lang": getLang(), ...(token ? { "X-CSRF-Token": token } : {}) },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  if (!response.ok) {
    let message = t("تعذر تنزيل الملف", "Could not download the file");
    try {
      const data = await response.json();
      if (typeof data?.detail === "string") message = data.detail;
    } catch {
      /* not JSON */
    }
    throw new ApiError(response.status, message);
  }
  const url = URL.createObjectURL(await response.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return t("حدث خطأ غير متوقع", "An unexpected error occurred");
}
