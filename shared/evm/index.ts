/**
 * Punto de entrada del analizador EVM: recibe el método y los parámetros
 * JSON-RPC que la página manda a la wallet y devuelve un Analysis.
 */
import { maxRisk, riskAtLeast, type RiskLevel, type Strictness } from '../risk';
import { AnalysisContext, type AnalysisInput } from './context';
import { analyzeEthSign, analyzePersonalSign, personalSignMessage } from './message';
import { analyzeBatch, analyzeTx, parseTx, Report } from './tx';
import { analyzeTypedData, parseTypedData } from './typed-data';
import { isAddress, normAddr } from './hex';
import type { Analysis, Lookup } from './types';

export { SENSITIVE_METHODS as SENSITIVE_EVM_METHODS } from '../bridge';

function typedDataParam(params: readonly unknown[]): unknown {
  // MetaMask: [dirección, datos]; algunas dapps invierten el orden.
  const [a, b] = params;
  if (isAddress(a)) return b;
  return isAddress(b) ? a : (b ?? a);
}

function run(method: string, params: readonly unknown[], ctx: AnalysisContext): Analysis {
  const r = new Report();
  let hardBlockInStrict = false;
  switch (method) {
    case 'eth_sendTransaction':
    case 'eth_signTransaction': {
      const tx = parseTx(params[0]);
      if (!tx) r.add({ code: 'undecodable', risk: 'high', text: 'No se pudo leer la transacción.' });
      else analyzeTx(ctx, r, tx);
      if (!r.title) r.setTitle('Transacción');
      break;
    }
    case 'wallet_sendCalls': {
      const p = params[0] as { calls?: unknown; from?: unknown } | undefined;
      if (!p || !Array.isArray(p.calls)) r.add({ code: 'undecodable', risk: 'high', text: 'No se pudo leer el lote de operaciones.' });
      else analyzeBatch(ctx, r, p.calls, normAddr(p.from));
      break;
    }
    case 'eth_sign':
      analyzeEthSign(r);
      hardBlockInStrict = true;
      break;
    case 'personal_sign': {
      const msg = personalSignMessage(params);
      if (msg === null) r.add({ code: 'undecodable', risk: 'medium', text: 'No se pudo leer el mensaje a firmar.' });
      else analyzePersonalSign(ctx, r, msg);
      break;
    }
    case 'eth_signTypedData_v3':
    case 'eth_signTypedData_v4': {
      const td = parseTypedData(typedDataParam(params));
      if (!td) r.add({ code: 'undecodable', risk: 'high', text: 'No se pudo leer la firma estructurada (EIP-712).' });
      else analyzeTypedData(ctx, r, td);
      break;
    }
    case 'eth_signTypedData':
    case 'eth_signTypedData_v1':
      r.setTitle('Firma de datos (formato antiguo)');
      r.add({ code: 'legacy-typed-data', risk: 'medium', text: 'Formato de firma antiguo (v1) que casi ninguna dapp actual usa.' });
      break;
    case 'wallet_grantPermissions':
      r.setTitle('Conceder permisos de sesión a la dapp');
      r.add({ code: 'grant-permissions', risk: 'high', text: 'La dapp pide permisos para operar en tu nombre sin pedirte cada firma (ERC-7715).' });
      break;
    case 'wallet_addEthereumChain':
      r.setTitle('Agregar una red');
      r.add({ code: 'add-chain', risk: 'low', text: 'Agregar una red con un RPC desconocido puede mostrarte saldos falsos.' });
      break;
    default:
      r.add({ code: 'unknown-method', risk: 'low', text: `Método ${method.slice(0, 60)}.` });
  }

  // Sitio sospechoso (heurísticas de dominio) + cualquier transacción o firma de datos → alto.
  // Solo se exceptúan los mensajes de texto y el login del propio sitio.
  const siteRisk = ctx.input.siteRisk;
  const harmless = r.findings.length > 0 && r.findings.every((f) => f.code === 'text-message' || f.code === 'siwe' || f.code === 'add-chain');
  if (riskAtLeast(siteRisk, 'medium') && !harmless) {
    r.add({
      code: 'suspicious-site',
      risk: 'high',
      text: `Además, ${ctx.input.pageHost} parece imitar a un sitio conocido.`,
    });
  }
  // Scripts sospechosos detectados en la página: cualquier firma pasa a alto.
  for (const t of ctx.input.pageThreats ?? []) {
    if (t.risk === 'high' || (t.risk === 'medium' && !harmless)) {
      r.add({ code: 'malicious-script', risk: t.risk === 'high' ? 'high' : 'medium', text: `Esta página ${t.text}` });
    }
  }
  return {
    method,
    risk: r.risk,
    title: r.title || method,
    summary: r.summary.slice(0, 40),
    findings: r.findings,
    hardBlockInStrict,
  };
}

/** Primera pasada: qué datos on-chain necesita el análisis. */
export function lookupsFor(method: string, params: readonly unknown[], input: AnalysisInput): Lookup[] {
  const ctx = new AnalysisContext(input);
  try {
    run(method, params, ctx);
  } catch {
    /* la segunda pasada reporta el error */
  }
  return [...ctx.pending.values()].slice(0, 16);
}

export function analyzeRequest(method: string, params: readonly unknown[], input: AnalysisInput): Analysis {
  const ctx = new AnalysisContext(input);
  try {
    return run(method, params, ctx);
  } catch (e) {
    return {
      method,
      risk: 'high',
      title: 'No se pudo analizar la solicitud',
      summary: [],
      findings: [{ code: 'undecodable', risk: 'high', text: `Error al analizar: ${e instanceof Error ? e.message.slice(0, 120) : 'desconocido'}.` }],
      hardBlockInStrict: false,
    };
  }
}

/** A partir de qué riesgo se muestra el modal, según la estricteza. */
export function modalThreshold(s: Strictness): RiskLevel {
  return s === 'relaxed' ? 'high' : s === 'normal' ? 'medium' : 'low';
}

export { maxRisk };
export type { Analysis, Lookup } from './types';
export type { AnalysisInput } from './context';
