// SPDX-License-Identifier: AGPL-3.0
/**
 * Minimal SBA-Auth example server. Reads are session-gated; the one
 * mutation is request-gated: each call needs its own wallet signature
 * bound to method + path + body. Run end-to-end via `npm run demo`.
 */

import express from 'express';
import { createPublicClient, http, type Address } from 'viem';
import {
  sbaSessionAuth,
  sbaRequestAuth,
  makeViemPredicate,
  deriveIdentityLocal,
  type SbaConfig,
} from '../server/sba-auth.js';

export interface ExampleServerOptions {
  rpcUrl: string;
  chainId: number;
  registry: Address;
  allowlist: string[];
  salt?: string;
}

export function createApp(options: ExampleServerOptions) {
  const client = createPublicClient({ transport: http(options.rpcUrl) });
  const salt = options.salt ?? 'SBA_SALT_V1';

  const config: SbaConfig = {
    chainId: options.chainId,
    verifyingContract: options.registry,
    predicate: makeViemPredicate(client, options.registry),
    deriveIdentity: (address) => deriveIdentityLocal(address, salt, options.chainId),
    allowlist: options.allowlist,
  };

  const sessionAuth = sbaSessionAuth(config);
  const requestAuth = sbaRequestAuth(config);

  const app = express();
  app.use(express.json({
    verify: (req, _res, buf) => { (req as { rawBody?: string }).rawBody = buf.toString('utf8'); },
  }));

  app.get('/admin/status', sessionAuth, (req, res) => {
    res.json({ ok: true, as: req.sbaAuth?.identityId, mode: req.sbaAuth?.mode });
  });

  app.post('/admin/action', requestAuth, (req, res) => {
    res.json({ ok: true, did: req.body?.action ?? null, as: req.sbaAuth?.identityId, mode: req.sbaAuth?.mode });
  });

  return { app, sessionAuth };
}
