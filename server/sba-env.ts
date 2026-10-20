// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Environment-file configuration for SBA-Auth.
 *
 * The whole authentication configuration of a deployment is five values,
 * none of them secret: the chain, the registry address, the purpose
 * string that names this console, the identity salt, and the allowlist
 * of enrolled identity values. Anyone who reads them learns who is
 * authorized and still cannot sign as any of them, so they belong in
 * ordinary change-controlled deployment configuration, and this module
 * reads them from there. Onboarding is one enrollment and one new
 * allowlist entry; offboarding is deleting the entry and redeploying.
 *
 * Every value is validated loudly at startup: a missing, empty, zero, or
 * malformed variable throws before any middleware is constructed. A
 * default never stands in for an absent value (see the zero-semantics
 * entry in audits/).
 *
 * The result is spread into an `SbaConfig` together with the two things
 * an environment file cannot hold, a predicate (needs a chain client)
 * and, for request mode, a `summaryOf` (needs the application's action
 * shape):
 *
 *   const env = sbaConfigFromEnv();
 *   const config = {
 *     ...env,
 *     predicate: makeViemPredicate(publicClient, env.verifyingContract),
 *     summaryOf: (req) => `withdraw ${req.body.amount} ${req.body.token} to ${req.body.to}`,
 *   };
 */

import type { Address, Hex } from 'viem';
import { deriveIdentityLocal, type SbaConfig } from './sba-auth.js';

/** Variable names read by `sbaConfigFromEnv`. Pass your own mapping to
 *  rename them; the semantics do not change. */
export const SBA_ENV = {
  chainId: 'SBA_CHAIN_ID',
  registry: 'SBA_REGISTRY',
  purpose: 'SBA_PURPOSE',
  identitySalt: 'SBA_IDENTITY_SALT',
  allowlist: 'SBA_ALLOWLIST',
} as const;

export type SbaEnvNames = { [K in keyof typeof SBA_ENV]: string };

/** The part of `SbaConfig` an environment file can supply, plus the
 *  salt it was derived from. */
export type SbaEnvConfig = Pick<
  SbaConfig,
  'chainId' | 'verifyingContract' | 'purpose' | 'deriveIdentity'
> & {
  allowlist: string[];
  identitySalt: string;
};

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = /^0x0{40}$/;
const IDENTITY = /^0x[0-9a-fA-F]{64}$/;
const ZERO_IDENTITY = /^0x0{64}$/;

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`sba-auth: ${name} is required and has no default`);
  }
  return value.trim();
}

/** Read and validate the deployment's authentication configuration.
 *  Throws on anything missing, empty, zero, or malformed. */
export function sbaConfigFromEnv(
  env: Record<string, string | undefined> = process.env,
  names: SbaEnvNames = SBA_ENV,
): SbaEnvConfig {
  const chainIdRaw = required(env, names.chainId);
  if (!/^[1-9]\d*$/.test(chainIdRaw) || !Number.isSafeInteger(Number(chainIdRaw))) {
    throw new Error(`sba-auth: ${names.chainId} must be a positive integer`);
  }
  const chainId = Number(chainIdRaw);

  const registry = required(env, names.registry);
  if (!ADDRESS.test(registry) || ZERO_ADDRESS.test(registry)) {
    throw new Error(`sba-auth: ${names.registry} must be a non-zero address (domain binding is mandatory)`);
  }
  const verifyingContract = registry as Address;

  const purpose = required(env, names.purpose);
  const identitySalt = required(env, names.identitySalt);

  const allowlist = Array.from(new Set(
    required(env, names.allowlist)
      .split(/[,\s]+/)
      .filter((entry) => entry.length > 0)
      .map((entry) => entry.toLowerCase()),
  ));
  if (allowlist.length === 0) {
    throw new Error(`sba-auth: ${names.allowlist} must list at least one enrolled identity value`);
  }
  for (const entry of allowlist) {
    if (!IDENTITY.test(entry)) {
      throw new Error(`sba-auth: ${names.allowlist} entry is not a 32-byte identity value: ${entry}`);
    }
    if (ZERO_IDENTITY.test(entry)) {
      throw new Error(`sba-auth: ${names.allowlist} contains the zero identity (absence can never be authorized)`);
    }
  }

  return {
    chainId,
    verifyingContract,
    purpose,
    identitySalt,
    allowlist,
    deriveIdentity: (address: Address): Hex => deriveIdentityLocal(address, identitySalt, chainId),
  };
}
