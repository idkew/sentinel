-- Run this ONCE in Supabase: SQL Editor > New query > paste > Run.

create table if not exists public.panel_kv (
  key        text primary key,
  value      jsonb not null,
  version    integer not null default 1,
  updated_at timestamptz not null default now()
);

-- Lock the table: with row level security on and no policies, only your secret key can touch it.
alter table public.panel_kv enable row level security;
revoke all on public.panel_kv from anon, authenticated;

-- Saves several rows together, or none at all, and refuses if another request changed a row first.
create or replace function public.panel_commit(changes jsonb) returns boolean
language plpgsql as $$
declare
  c jsonb;
  n integer;
begin
  for c in select e from jsonb_array_elements(changes) as t(e) loop
    if (c->>'expect')::integer = 0 then
      insert into public.panel_kv (key, value, version) values (c->>'key', c->'value', 1) on conflict (key) do nothing;
    else
      update public.panel_kv
         set value = c->'value', version = version + 1, updated_at = now()
       where key = c->>'key' and version = (c->>'expect')::integer;
    end if;
    get diagnostics n = row_count;
    if n = 0 then
      raise exception 'conflict' using errcode = '40001';
    end if;
  end loop;
  return true;
exception when serialization_failure then
  return false;
end;
$$;

-- Only the secret key may call it, never the public keys.
revoke all on function public.panel_commit(jsonb) from public, anon, authenticated;
grant execute on function public.panel_commit(jsonb) to service_role;
