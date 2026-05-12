-- Round 5 Step 2 — additive migration for legacy → MCP audience cutover.
--
-- The 4 service-to-service oauth_clients rows (bsgateway-prod / bsage-prod /
-- bsnexus-prod / bsupervisor-prod) currently allow only the legacy ``bs*``
-- audiences + dot-grammar scopes. Step 3 will flip producers to mint the
-- new MCP-aligned audiences (sage / gateway / supervisor / nexus) +
-- colon-grammar scopes (e.g. ``supervisor:audit.write``).
--
-- This migration grants the new aud/scope ADDITIVELY so producers can
-- request either during the rollout. Step 4 (after all producers + the
-- bsvibe-authz library + the consuming validators flip) removes the legacy
-- values, leaving only the new ones.

-- bsgateway-prod  → currently aud=[bsupervisor], scope=[bsupervisor.write]
-- bsage-prod      → currently aud=[bsupervisor], scope=[bsupervisor.write]
update public.oauth_clients
   set allowed_audiences = array_append(
         array_remove(allowed_audiences, 'supervisor'),
         'supervisor'
       ),
       allowed_scopes = array_append(
         array_remove(allowed_scopes, 'supervisor:audit.write'),
         'supervisor:audit.write'
       )
 where client_id in ('bsgateway-prod', 'bsage-prod');

-- bsnexus-prod    → currently aud=[bsage, bsupervisor],
--                              scope=[bsage.read, bsupervisor.write]
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(distinct a)
           from unnest(allowed_audiences || array['sage', 'supervisor']) as a
       ),
       allowed_scopes = (
         select array_agg(distinct s)
           from unnest(
             allowed_scopes ||
             array['sage:read', 'supervisor:audit.write']
           ) as s
       )
 where client_id = 'bsnexus-prod';

-- bsupervisor-prod has no outbound calls today; aud + scope arrays stay
-- non-empty per CHECK constraint, so we synthesise a self-grant for the
-- supervisor audience even though nothing currently mints with it. The
-- row needs SOMETHING so the column constraints survive Step 4.
update public.oauth_clients
   set allowed_audiences = array_append(
         array_remove(allowed_audiences, 'supervisor'),
         'supervisor'
       ),
       allowed_scopes = array_append(
         array_remove(allowed_scopes, 'supervisor:audit.write'),
         'supervisor:audit.write'
       )
 where client_id = 'bsupervisor-prod';
