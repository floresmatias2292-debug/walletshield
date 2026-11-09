/**
 * Consulta opcional (desactivada por defecto) de la fecha de registro de un
 * dominio vía RDAP. Envía el nombre de dominio a rdap.org y al registro
 * correspondiente, por eso solo se usa si el usuario la activa y solo para
 * dominios que las heurísticas ya marcaron como sospechosos.
 */
const TIMEOUT_MS = 2500;

export function parseRegistrationDate(json: unknown): number | null {
  if (typeof json !== 'object' || json === null) return null;
  const events = (json as { events?: unknown }).events;
  if (!Array.isArray(events)) return null;
  for (const e of events) {
    if (typeof e !== 'object' || e === null) continue;
    const { eventAction, eventDate } = e as { eventAction?: unknown; eventDate?: unknown };
    if (eventAction === 'registration' && typeof eventDate === 'string') {
      const t = Date.parse(eventDate);
      return Number.isFinite(t) ? t : null;
    }
  }
  return null;
}

export async function domainAgeDays(registrable: string, fetchImpl: typeof fetch = fetch): Promise<number | null> {
  const key = `rdap:${registrable}`;
  const cached = await chrome.storage.session.get(key);
  if (typeof cached[key] === 'number') return cached[key] as number;
  try {
    const res = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(registrable)}`, {
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { Accept: 'application/rdap+json' },
    });
    if (!res.ok) return null;
    const reg = parseRegistrationDate(await res.json());
    if (reg === null) return null;
    const days = Math.floor((Date.now() - reg) / 86_400_000);
    await chrome.storage.session.set({ [key]: days });
    return days;
  } catch {
    return null;
  }
}
