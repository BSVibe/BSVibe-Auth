-- Post-Round-5 reversion (Step 2 of 2) — STRICT cutover, drop the bare-name
-- audiences + bare-prefix scopes from every oauth_clients row. Only the
-- ``bs``-prefixed canonical forms remain.
--
-- 20260515_000001 granted the ``bs``-prefixed audiences/scopes ADDITIVELY
-- so a rolling product deploy stayed graceful while every product backend
-- cut over. The 4 product backends are now live on the ``bs*`` forms
-- (autodeploy state confirmed 2026-05-15, .deployed matches origin/main
-- for BSGateway 4c8183a / BSupervisor 7fc907a / BSage fddc4e08 /
-- BSNexus 22e986c). This migration removes the bare-name siblings so a
-- misconfigured producer can never silently fall back to the legacy
-- grammar.
--
-- ``bsvibe-auth`` audience/scopes are the internal audit-relay carve-out
-- and stay untouched.

-- claude-code-mcp / cli — drop the bare audiences + bare prefix-wildcard
-- scopes; the ``bs*`` siblings (granted by 20260515_000001) stay.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(a)
           from unnest(allowed_audiences) as a
          where a not in ('gateway', 'sage', 'nexus', 'supervisor')
       ),
       allowed_scopes = (
         select array_agg(s)
           from unnest(allowed_scopes) as s
          where s not in ('gateway:*', 'sage:*', 'nexus:*', 'supervisor:*')
       )
 where client_id in ('claude-code-mcp', 'cli');

-- bsgateway-prod / bsage-prod / bsupervisor-prod — drop the bare
-- ``supervisor`` audience + colon-grammar bare scope.
update public.oauth_clients
   set allowed_audiences = array_remove(allowed_audiences, 'supervisor'),
       allowed_scopes = array_remove(allowed_scopes, 'supervisor:audit.write')
 where client_id in ('bsgateway-prod', 'bsage-prod', 'bsupervisor-prod');

-- bsnexus-prod — drop the bare ``sage`` + ``supervisor`` audiences and
-- the matching bare colon-grammar scopes.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(a)
           from unnest(allowed_audiences) as a
          where a not in ('sage', 'supervisor')
       ),
       allowed_scopes = (
         select array_agg(s)
           from unnest(allowed_scopes) as s
          where s not in ('sage:read', 'supervisor:audit.write')
       )
 where client_id = 'bsnexus-prod';
