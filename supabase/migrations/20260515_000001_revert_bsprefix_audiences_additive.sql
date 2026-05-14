-- Post-Round-5 reversion (Step 1 of 2) — ADDITIVELY grant the ``bs``-prefixed
-- audiences + scopes back to every oauth_clients row.
--
-- Round 5 moved service-token audiences to bare names (gateway / sage /
-- supervisor / nexus). We are reverting to ``bs``-prefixed product names
-- (bsgateway / bsage / bsupervisor / bsnexus) so audience and product
-- identity match everywhere again.
--
-- This migration is ADDITIVE so a rolling product deploy stays graceful:
-- a producer minting either the bare or the bs-prefixed audience is
-- accepted while the 4 product backends cut over. The companion strict
-- migration (Step 2) removes the bare-name entries once every product
-- backend is live on the bs-prefixed values.
--
-- ``bsvibe-auth`` audience/scopes are the internal audit-relay carve-out
-- and are left untouched.

-- claude-code-mcp — MCP authorization_code client.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(distinct a)
           from unnest(
             allowed_audiences ||
             array['bsgateway', 'bsage', 'bsnexus', 'bsupervisor']
           ) as a
       ),
       allowed_scopes = (
         select array_agg(distinct s)
           from unnest(
             allowed_scopes ||
             array['bsgateway:*', 'bsage:*', 'bsnexus:*', 'bsupervisor:*']
           ) as s
       )
 where client_id = 'claude-code-mcp';

-- cli — RFC 8628 device-flow client used by every product CLI.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(distinct a)
           from unnest(
             allowed_audiences ||
             array['bsgateway', 'bsage', 'bsnexus', 'bsupervisor']
           ) as a
       ),
       allowed_scopes = (
         select array_agg(distinct s)
           from unnest(
             allowed_scopes ||
             array['bsgateway:*', 'bsage:*', 'bsnexus:*', 'bsupervisor:*']
           ) as s
       )
 where client_id = 'cli';

-- bsgateway-prod / bsage-prod / bsupervisor-prod — outbound calls to
-- BSupervisor's audit sink.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(distinct a)
           from unnest(allowed_audiences || array['bsupervisor']) as a
       ),
       allowed_scopes = (
         select array_agg(distinct s)
           from unnest(allowed_scopes || array['bsupervisor:audit.write']) as s
       )
 where client_id in ('bsgateway-prod', 'bsage-prod', 'bsupervisor-prod');

-- bsnexus-prod — outbound calls to BSage (knowledge) and BSupervisor (audit).
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(distinct a)
           from unnest(allowed_audiences || array['bsage', 'bsupervisor']) as a
       ),
       allowed_scopes = (
         select array_agg(distinct s)
           from unnest(
             allowed_scopes ||
             array['bsage:read', 'bsupervisor:audit.write']
           ) as s
       )
 where client_id = 'bsnexus-prod';
