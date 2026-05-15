-- Tier 2 (final step) — drop the opaque-token columns from public.tokens.
--
-- Issuance of ``bsv_sk_*`` / ``bsv_pk_*`` opaque API keys died with the
-- Tier-1 surface cleanup (POST /api/tokens / service-tokens/issue removed).
-- The prefix dispatch in bsvibe-authz died in 1.3.0 (deps.py + auth.py:
-- verify_opaque_token → verify_via_introspection, OPAQUE_TOKEN_PREFIX
-- deleted). Nothing reads or writes ``tokens.prefix`` / ``tokens.token_hash``
-- now — the columns are dead weight + an index that costs writes.
--
-- Forward-only DROP. PAT JWTs (``tokens.type='pat'``) carry no prefix/hash —
-- they're identified by ``jti`` (existing unique index). Refresh tokens
-- live in ``public.refresh_tokens`` (separate table), unaffected.

drop index if exists public.tokens_prefix_idx;

alter table public.tokens
  drop column if exists prefix,
  drop column if exists token_hash;
