import { getLang, t } from "./i18n";
import { DEVICE_TYPES, label } from "./labels";

// Latin digits keep dates consistent with IPs, ports and MAC addresses in both languages.
const dateTimeAr = new Intl.DateTimeFormat("ar-EG-u-nu-latn", { dateStyle: "medium", timeStyle: "short" });
const dateTimeEn = new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short" });
const numberAr = new Intl.NumberFormat("ar-EG-u-nu-latn");
const numberEn = new Intl.NumberFormat("en-US");

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return (getLang() === "en" ? dateTimeEn : dateTimeAr).format(d);
}

export function formatNumber(value: number): string {
  return (getLang() === "en" ? numberEn : numberAr).format(value);
}

export function percent(confidence: number): string {
  return `${Math.round(Math.max(0, Math.min(1, confidence)) * 100)}%`;
}

export function deviceTypeSentence(deviceType: string, confidence: number): string {
  if (deviceType === "unknown" || confidence <= 0)
    return t("نوع الجهاز: غير مؤكد — يتطلب مراجعة", "Device type: unconfirmed — needs review");
  const type = label(DEVICE_TYPES, deviceType);
  return getLang() === "en"
    ? `Device type: ${type} — confidence ${percent(confidence)}`
    : `نوع الجهاز: ${type} — الثقة ${percent(confidence)}`;
}

export function splitList(text: string): string[] {
  return text
    .split(/[\s,،]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parsePorts(text: string): number[] | null {
  const items = splitList(text);
  const ports = items.map((s) => Number(s));
  if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return null;
  return ports;
}

export function progress(processed: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.round((processed / total) * 100));
}
