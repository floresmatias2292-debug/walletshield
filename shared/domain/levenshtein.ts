/**
 * Distancia de Damerau-Levenshtein (variante "optimal string alignment":
 * inserción, borrado, sustitución y transposición de adyacentes) con corte
 * temprano: si la distancia supera `max`, devuelve `max + 1` sin terminar
 * de llenar la matriz. Usa tres filas, memoria O(n).
 */
export function boundedDistance(a: string, b: string, max: number): number {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > max) return max + 1;
  if (la === 0) return lb;
  if (lb === 0) return la;

  let prev2 = new Array<number>(lb + 1).fill(0);
  let prev = new Array<number>(lb + 1);
  let cur = new Array<number>(lb + 1);
  for (let j = 0; j <= lb; j++) prev[j] = j;

  for (let i = 1; i <= la; i++) {
    cur[0] = i;
    let rowMin = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= lb; j++) {
      const cb = b.charCodeAt(j - 1);
      const cost = ca === cb ? 0 : 1;
      let v = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + cost);
      if (i > 1 && j > 1 && ca === b.charCodeAt(j - 2) && a.charCodeAt(i - 2) === cb) {
        v = Math.min(v, prev2[j - 2]! + 1);
      }
      cur[j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > max) return max + 1;
    const tmp = prev2;
    prev2 = prev;
    prev = cur;
    cur = tmp;
  }
  const d = prev[lb]!;
  return d > max ? max + 1 : d;
}
