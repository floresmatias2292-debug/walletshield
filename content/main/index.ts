/**
 * WalletShield — script en el contexto de la página (world: MAIN).
 *
 * Corre en document_start, antes que cualquier script de la página. Envuelve
 * window.ethereum y los providers anunciados por EIP-6963 con un Proxy:
 *  - los métodos de lectura pasan directo (costo ≈ una búsqueda en un Set);
 *  - los sensibles (firmas, transacciones) se retienen hasta que el script
 *    aislado los analiza y, si hace falta, el usuario decide en el modal.
 *
 * Debe ser chico y no depender de nada que la página pueda alterar: guarda
 * referencias a las funciones nativas apenas arranca.
 */
import { HANDSHAKE_KEY, parseIsoToMain, READONLY_RPC, safeClone, SENSITIVE_METHODS } from '../../shared/bridge';
import { READONLY_CALL_SELECTORS } from '../../shared/evm/selectors';

(() => {
  // ── referencias nativas (la página podría reemplazarlas después) ──────────
  const W = window;
  const defineProperty = Object.defineProperty;
  const definePropertiesNative = Object.defineProperties;
  const reflectDefineProperty = Reflect.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectCreate = Object.create;
  const freeze = Object.freeze;
  const reflectGet = Reflect.get;
  const reflectSet = Reflect.set;
  const reflectApply = Reflect.apply;
  const ProxyC = Proxy;
  const WeakMapC = WeakMap;
  const WeakSetC = WeakSet;
  const MapC = Map;
  const PromiseC = Promise;
  const ErrorC = Error;
  const isArray = Array.isArray;
  const setTimeoutF = W.setTimeout.bind(W);
  const clearTimeoutF = W.clearTimeout.bind(W);
  const addEvent = EventTarget.prototype.addEventListener;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const CustomEventC = CustomEvent;
  const stopImmediate = Event.prototype.stopImmediatePropagation;

  const ACK_TIMEOUT_MS = 2500;
  const RPC_TIMEOUT_MS = 1500;

  // ── canal privado con el script aislado ───────────────────────────────────
  const channel = new MessageChannel();
  const port = channel.port1;
  W.postMessage({ [HANDSHAKE_KEY]: true }, '*', [channel.port2]);

  type Pending = { resolve: (allow: boolean) => void; acked: boolean; target: object; timer: number };
  const pending = new MapC<number, Pending>();
  let seq = 0;

  function frameInfo() {
    let top = false;
    try {
      top = W.top === W;
    } catch {
      top = false;
    }
    return { top, w: W.innerWidth, h: W.innerHeight };
  }

  function rpcError(message: string, code = 4001): Error {
    const e = new ErrorC(message) as Error & { code: number };
    e.code = code;
    return e;
  }

  /** Pide decisión al script aislado. Falla cerrado si no responde. */
  function askIsolated(target: object, method: string, params: unknown, ns: 'evm' | 'solana'): Promise<boolean> {
    return new PromiseC<boolean>((resolve) => {
      const id = ++seq;
      const cloned = safeClone(params === undefined ? [] : params);
      const timer = setTimeoutF(() => {
        const p = pending.get(id);
        if (p && !p.acked) {
          pending.delete(id);
          resolve(false);
        }
      }, ACK_TIMEOUT_MS);
      pending.set(id, { resolve, acked: false, target, timer });
      port.postMessage({
        t: 'req',
        id,
        method,
        params: cloned ?? [{ __walletshield_unreadable__: true }],
        frame: frameInfo(),
        ns,
      });
    });
  }

  port.onmessage = (ev: MessageEvent) => {
    const msg = parseIsoToMain(ev.data);
    if (!msg) return;
    if (msg.t === 'ack') {
      const p = pending.get(msg.id);
      if (p) {
        p.acked = true;
        clearTimeoutF(p.timer);
      }
    } else if (msg.t === 'decision') {
      const p = pending.get(msg.id);
      if (p) {
        pending.delete(msg.id);
        p.resolve(msg.allow);
      }
    } else if (msg.t === 'rpc') {
      void runReadonly(msg.id, msg.reqId, msg.method, msg.params);
    }
  };

  /** Lecturas on-chain para el análisis, siempre vía la propia wallet y solo de lectura. */
  async function runReadonly(id: number, reqId: number, method: string, params: unknown[]): Promise<void> {
    const p = pending.get(reqId);
    let ok = false;
    let result: unknown = null;
    try {
      if (!p || !READONLY_RPC.has(method)) throw new ErrorC('no permitido');
      if (method === 'eth_call') {
        const call = params[0] as { to?: unknown; data?: unknown } | undefined;
        const data = typeof call?.data === 'string' ? call.data : '';
        if (data.length > 74 || !READONLY_CALL_SELECTORS.has(data.slice(0, 10))) throw new ErrorC('llamada no permitida');
      }
      const raw = rawOf.get(p.target);
      const request = raw ? (reflectGet(raw, 'request', raw) as unknown) : null;
      if (typeof request !== 'function') throw new ErrorC('sin provider');
      result = await new PromiseC((resolve, reject) => {
        const t = setTimeoutF(() => reject(new ErrorC('timeout')), RPC_TIMEOUT_MS);
        (reflectApply(request, raw, [{ method, params }]) as Promise<unknown>).then(
          (v) => {
            clearTimeoutF(t);
            resolve(v);
          },
          (e: unknown) => {
            clearTimeoutF(t);
            reject(e);
          },
        );
      });
      ok = true;
    } catch {
      ok = false;
    }
    port.postMessage({ t: 'rpc-res', id, ok, result: safeClone([result])?.[0] ?? null });
  }

  // ── envoltura de providers ────────────────────────────────────────────────
  const proxies = new WeakSetC<object>();
  const proxyOf = new WeakMapC<object, object>();
  const rawOf = new WeakMapC<object, object>(); // proxy → provider real

  function rpcPayload(v: unknown): { method: string; params: unknown } | null {
    if (typeof v !== 'object' || v === null) return null;
    const m = (v as { method?: unknown }).method;
    return typeof m === 'string' ? { method: m, params: (v as { params?: unknown }).params } : null;
  }

  function sensitivePayloads(arg: unknown): Array<{ method: string; params: unknown }> {
    const list = isArray(arg) ? arg : [arg];
    const out: Array<{ method: string; params: unknown }> = [];
    for (const x of list) {
      const p = rpcPayload(x);
      if (p && SENSITIVE_METHODS.has(p.method)) out.push(p);
    }
    return out;
  }

  async function approveAll(proxy: object, items: Array<{ method: string; params: unknown }>, ns: 'evm' | 'solana'): Promise<boolean> {
    for (const it of items) if (!(await askIsolated(proxy, it.method, it.params, ns))) return false;
    return true;
  }

  const BLOCKED_MSG = 'WalletShield bloqueó esta solicitud. Si fue un error, ábrela de nuevo y elige "Continuar".';

  function looksLikeProvider(v: unknown): v is object {
    return typeof v === 'object' && v !== null && typeof (v as { request?: unknown }).request === 'function';
  }

  function wrapProvider<T>(p: T, ns: 'evm' | 'solana' = 'evm'): T {
    if (typeof p !== 'object' || p === null) return p;
    const obj = p as unknown as object;
    if (proxies.has(obj)) return p;
    const cached = proxyOf.get(obj);
    if (cached) return cached as T;

    const fnCache = new MapC<PropertyKey, { orig: unknown; wrapped: unknown }>();
    // El target del Proxy es un objeto vacío que hereda del provider: así no
    // chocamos con los invariantes de Proxy si el provider está congelado.
    const shell = objectCreate(obj) as object;
    let proxy: object;

    const fixReturn = (r: unknown): unknown => (r === obj ? proxy : r);

    function wrapFn(prop: PropertyKey, fn: (...a: unknown[]) => unknown): unknown {
      const hit = fnCache.get(prop);
      if (hit && hit.orig === fn) return hit.wrapped;
      let wrapped: unknown;
      if (prop === 'request') {
        wrapped = function request(args: unknown) {
          const items = sensitivePayloads(args);
          if (items.length === 0) return fixReturn(reflectApply(fn, obj, [args]));
          return approveAll(proxy, items, ns).then((ok) => {
            if (!ok) throw rpcError(BLOCKED_MSG);
            return reflectApply(fn, obj, [args]);
          });
        };
      } else {
        // send, sendAsync, enable, _rpcRequest y cualquier otro método: si recibe
        // un payload JSON-RPC sensible (incluso por métodos internos), se analiza.
        wrapped = function (this: unknown, ...args: unknown[]) {
          let items = sensitivePayloads(args[0]);
          // send('eth_sign', [..]) — firma legacy (método como string)
          if (items.length === 0 && typeof args[0] === 'string' && SENSITIVE_METHODS.has(args[0])) {
            items = [{ method: args[0], params: args[1] }];
          }
          if (items.length === 0) return fixReturn(reflectApply(fn, obj, args));
          const cb = args[args.length - 1];
          const check = approveAll(proxy, items, ns);
          if (typeof cb === 'function') {
            void check.then((ok) => {
              if (ok) reflectApply(fn, obj, args);
              else reflectApply(cb, undefined, [rpcError(BLOCKED_MSG), null]);
            });
            return undefined;
          }
          return check.then((ok) => {
            if (!ok) throw rpcError(BLOCKED_MSG);
            return reflectApply(fn, obj, args);
          });
        };
      }
      fnCache.set(prop, { orig: fn, wrapped });
      return wrapped;
    }

    proxy = new ProxyC(shell, {
      get(_t, prop) {
        const v = reflectGet(obj, prop, obj) as unknown;
        if (typeof v === 'function') return wrapFn(prop, v as (...a: unknown[]) => unknown);
        if (v === obj) return proxy;
        if (looksLikeProvider(v)) return wrapProvider(v, ns);
        if (isArray(v) && v.some(looksLikeProvider)) return v.map((x) => (looksLikeProvider(x) ? wrapProvider(x, ns) : x));
        return v;
      },
      set(_t, prop, value) {
        return reflectSet(obj, prop, value, obj);
      },
      has(_t, prop) {
        return prop in obj;
      },
      getOwnPropertyDescriptor(_t, prop) {
        const d = getOwnPropertyDescriptor(obj, prop);
        return d ? { ...d, configurable: true } : undefined;
      },
      defineProperty(_t, prop, desc) {
        return reflectDefineProperty(obj, prop, desc);
      },
    });
    proxies.add(proxy);
    proxyOf.set(obj, proxy);
    rawOf.set(proxy, obj);
    return proxy as T;
  }

  // ── window.ethereum: interceptar asignaciones y defineProperty ───────────
  type Source = { kind: 'value'; v: unknown } | { kind: 'accessor'; get?: () => unknown; set?: (v: unknown) => void };

  function guardGlobal(key: string, ns: 'evm' | 'solana'): void {
    const existing = getOwnPropertyDescriptor(W, key);
    if (existing && !existing.configurable) {
      // La wallet fijó la propiedad como no configurable: solo podemos
      // reemplazar el valor si es escribible.
      if ('value' in existing && existing.writable && existing.value) {
        try {
          (W as unknown as Record<string, unknown>)[key] = wrapProvider(existing.value, ns);
        } catch {
          /* sin protección para esta propiedad: limitación documentada */
        }
      }
      return;
    }
    let src: Source = existing
      ? 'value' in existing
        ? { kind: 'value', v: existing.value }
        : { kind: 'accessor', ...(existing.get ? { get: existing.get } : {}), ...(existing.set ? { set: existing.set } : {}) }
      : { kind: 'value', v: undefined };

    const read = (): unknown => (src.kind === 'value' ? src.v : src.get ? reflectApply(src.get, W, []) : undefined);
    defineProperty(W, key, {
      configurable: true,
      enumerable: true,
      get() {
        return wrapProvider(read(), ns);
      },
      set(v: unknown) {
        if (src.kind === 'accessor' && src.set) reflectApply(src.set, W, [v]);
        else src = { kind: 'value', v };
      },
    });
    guarded.set(key, {
      redefine(desc: PropertyDescriptor) {
        if ('value' in desc) src = { kind: 'value', v: desc.value };
        else if (desc.get || desc.set) src = { kind: 'accessor', ...(desc.get ? { get: desc.get } : {}), ...(desc.set ? { set: desc.set } : {}) };
      },
    });
  }

  const guarded = new MapC<PropertyKey, { redefine(d: PropertyDescriptor): void }>();

  // Si una wallet (o un script) redefine window.ethereum con defineProperty,
  // conservamos nuestro accessor y solo cambiamos la fuente del valor.
  function patchedDefine<T>(target: T, prop: PropertyKey, desc: PropertyDescriptor & ThisType<unknown>): T {
    const g = target === (W as unknown) ? guarded.get(prop) : undefined;
    if (g && desc && typeof desc === 'object') {
      g.redefine(desc);
      return target;
    }
    return defineProperty(target, prop, desc) as T;
  }
  Object.defineProperty = patchedDefine as typeof Object.defineProperty;
  Reflect.defineProperty = function (target: object, prop: PropertyKey, desc: PropertyDescriptor): boolean {
    const g = target === (W as unknown) ? guarded.get(prop) : undefined;
    if (g) {
      g.redefine(desc);
      return true;
    }
    return reflectDefineProperty(target, prop, desc);
  };
  Object.defineProperties = function <T>(target: T, props: PropertyDescriptorMap & ThisType<unknown>): T {
    if (target === (W as unknown)) {
      for (const k of Reflect.ownKeys(props)) {
        const d = (props as Record<PropertyKey, PropertyDescriptor>)[k as string];
        if (d) patchedDefine(target, k, d);
      }
      return target;
    }
    return definePropertiesNative(target, props) as T;
  };

  guardGlobal('ethereum', 'evm');

  // ── EIP-6963: reemplazar el provider anunciado por uno envuelto ───────────
  const ours = new WeakSetC<Event>();
  reflectApply(addEvent, W, [
    'eip6963:announceProvider',
    (ev: Event) => {
      if (ours.has(ev)) return;
      const detail = (ev as CustomEvent<{ info?: unknown; provider?: unknown }>).detail;
      if (!detail || !looksLikeProvider(detail.provider)) return;
      const wrapped = wrapProvider(detail.provider, 'evm');
      if (wrapped === detail.provider) return;
      reflectApply(stopImmediate, ev, []);
      const ne = new CustomEventC('eip6963:announceProvider', { detail: freeze({ info: detail.info, provider: wrapped }) });
      ours.add(ne);
      reflectApply(dispatch, W, [ne]);
    },
    true,
  ]);
})();
