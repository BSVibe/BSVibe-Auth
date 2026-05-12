-- Round 5 Step 4 — strict cutover, remove the legacy bs* audiences + dot
-- grammar scopes from the 4 service-to-service oauth_clients rows.
--
-- Step 2 (20260514_000001) granted the new MCP-aligned audiences/scopes
-- additively. Step 3 flipped all 4 product backends (BSGateway / BSage /
-- BSNexus producers, BSupervisor consumer) to use the new values. Their
-- prod deploys are live. This migration now removes the legacy entries
-- from the allow-lists so a misconfigured producer can never silently fall
-- back to the legacy grammar.

-- bsgateway-prod / bsage-prod / bsupervisor-prod: drop legacy ``bsupervisor``
-- audience + ``bsupervisor.write`` scope.
update public.oauth_clients
   set allowed_audiences = array_remove(allowed_audiences, 'bsupervisor'),
       allowed_scopes = array_remove(allowed_scopes, 'bsupervisor.write')
 where client_id in ('bsgateway-prod', 'bsage-prod', 'bsupervisor-prod');

-- bsnexus-prod: drop legacy ``bsage`` + ``bsupervisor`` audiences and the
-- matching dot-grammar scopes.
update public.oauth_clients
   set allowed_audiences = (
         select array_agg(a)
           from unnest(allowed_audiences) as a
          where a not in ('bsage', 'bsupervisor')
       ),
       allowed_scopes = (
         select array_agg(s)
           from unnest(allowed_scopes) as s
          where s not in ('bsage.read', 'bsupervisor.write')
       )
 where client_id = 'bsnexus-prod';

-- ---------------------------------------------------------------------------
-- The ``cli`` and ``claude-code-mcp`` public clients (Round 5 device-flow /
-- authorization_code) already use the new audiences exclusively — no row
-- changes needed here for them.
-- ---------------------------------------------------------------------------
