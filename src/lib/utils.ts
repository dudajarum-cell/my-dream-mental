export function formatSeconds(total: number): string {
  const s = Math.max(0, Math.round(total || 0));
  if (s < 60) return `${s} soniya`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return r ? `${m} daqiqa ${r} soniya` : `${m} daqiqa`;
}

export function formatShort(total: number): string {
  const s = Math.max(0, Math.round(total || 0));
  const m = Math.floor(s / 60);
  if (m <= 0) return `${s}s`;
  return `${m}m ${s % 60}s`;
}

export function formatDateTime(tsSec: number | null | undefined): string {
  if (!tsSec) return "—";
  const d = new Date(tsSec * 1000);
  return d.toLocaleString("uz-UZ", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function formatDate(tsSec: number): string {
  return new Date(tsSec * 1000).toLocaleDateString("uz-UZ");
}

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

// O'zbekiston telefon raqami: +998-91-376-99-80
// +998, 998, 8 yoki 9 xonali lokal formatlarni qabul qiladi.
export function formatUzPhone(raw: string): string {
  let digits = String(raw || "").replace(/\D/g, "");
  if (digits.startsWith("998")) digits = digits.slice(3);
  else if (digits.length === 10 && digits.startsWith("8")) digits = digits.slice(1);
  digits = digits.slice(0, 9);
  const a = digits.slice(0, 2);
  const b = digits.slice(2, 5);
  const c = digits.slice(5, 7);
  const d = digits.slice(7, 9);
  let out = "+998-";
  if (a) out += a;
  if (b) out += `-${b}`;
  if (c) out += `-${c}`;
  if (d) out += `-${d}`;
  return out;
}

// Formatlangan raqamdan faqat 9 xonali lokal qismni qaytaradi.
export function uzPhoneDigits(raw: string): string {
  const digits = formatUzPhone(raw).replace(/\D/g, "");
  return digits.startsWith("998") ? digits.slice(3) : digits;
}

export function downloadCsv(filename: string, headers: string[], rows: (string | number | null | undefined)[][]): void {
  const esc = (v: unknown) => {
    const s = String(v ?? "");
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const body = "\uFEFF" + [headers.map(esc).join(","), ...rows.map((r) => r.map(esc).join(","))].join("\n");
  const blob = new Blob([body], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
