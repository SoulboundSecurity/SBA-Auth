// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Minimal SBA-Auth example server. Reads are session-gated; mutations
 * are request-gated: each call needs its own wallet signature bound to
 * method + full URL + body bytes. The same mutation is exposed twice, at
 * the root and under a mounted router, to show that the signed path is
 * the full original URL. Run end-to-end via `npm run demo`.
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

export const EXAMPLE_PURPOSE = 'SBA Example Console';

export interface ExampleServerOptions {
  rpcUrl: string;
  chainId: number;
  registry: Address;
  allowlist: string[];
  salt?: string;
  /** Default true. The demo sets false once to show that a request
   *  carrying a body with no raw-body capture is denied. */
  captureRawBody?: boolean;
  nonceCacheMax?: number;
}

export function createApp(options: ExampleServerOptions) {
  const client = createPublicClient({ transport: http(options.rpcUrl) });
  const salt = options.salt ?? 'SBA_SALT_V1';

  const config: SbaConfig = {
    chainId: options.chainId,
    verifyingContract: options.registry,
    purpose: EXAMPLE_PURPOSE,
    predicate: makeViemPredicate(client, options.registry),
    deriveIdentity: (address) => deriveIdentityLocal(address, salt, options.chainId),
    allowlist: options.allowlist,
    nonceCacheMax: options.nonceCacheMax,
  };

  const sessionAuth = sbaSessionAuth(config);
  const requestAuth = sbaRequestAuth(config);

  const app = express();
  app.use(express.json(
    options.captureRawBody === false
      ? {}
      : { verify: (req, _res, buf) => { (req as { rawBody?: string }).rawBody = buf.toString('utf8'); } },
  ));

  app.get('/admin/status', sessionAuth, (req, res) => {
    res.json({ ok: true, as: req.sbaAuth?.identityId, mode: req.sbaAuth?.mode });
  });

  const act: express.RequestHandler = (req, res) => {
    res.json({ ok: true, did: req.body?.action ?? null, as: req.sbaAuth?.identityId, mode: req.sbaAuth?.mode });
  };
  app.post('/admin/action', requestAuth, act);

  const mounted = express.Router();
  mounted.post('/action', requestAuth, act);
  app.use('/console', mounted);

  return { app, sessionAuth, config };
}
