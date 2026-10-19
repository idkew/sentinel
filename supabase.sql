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

-- ===== Added in Sentinel 5.5. Safe to run again: it only creates what is missing. =====

-- Chat logs: in-game chat grouped in boxes of up to 10 messages from one server.
create table if not exists public.chat_boxes (
  id         text primary key,              -- XXXXXXXXX-XXXXXXXX, unique across the whole site
  wid        text not null,                 -- workspace
  opened_at  timestamptz not null,
  closed_at  timestamptz not null,
  server     text not null,                 -- short game server id
  user_ids   bigint[] not null default '{}',
  names      text not null default '',      -- lower-case usernames, for search
  body       text not null default '',      -- lower-case message text, for search
  flagged    boolean not null default false,
  flag_types text[] not null default '{}',
  msgs       jsonb not null,
  bytes      integer not null default 0
);
create index if not exists chat_boxes_wid_closed on public.chat_boxes (wid, closed_at desc);
create index if not exists chat_boxes_users on public.chat_boxes using gin (user_ids);
create index if not exists chat_boxes_flags on public.chat_boxes using gin (flag_types);
alter table public.chat_boxes enable row level security;
revoke all on public.chat_boxes from anon, authenticated;

-- How many boxes and bytes a workspace uses.
create or replace function public.chat_box_usage(w text) returns table (n bigint, bytes bigint)
language sql stable as $$ select count(*), coalesce(sum(bytes), 0) from public.chat_boxes where wid = w $$;

-- Deletes a workspace's oldest boxes when it is over its limit.
create or replace function public.chat_box_trim(w text, max_n integer, max_bytes bigint) returns integer
language plpgsql as $$
declare
  cnt bigint; total bigint; removed integer := 0; k integer; d integer;
begin
  loop
    select count(*), coalesce(sum(bytes), 0) into cnt, total from public.chat_boxes where wid = w;
    exit when (cnt <= max_n and total <= max_bytes) or removed >= 5000;
    k := case when cnt > max_n then least(500, cnt - max_n)::integer else 200 end;
    delete from public.chat_boxes where id in (select id from public.chat_boxes where wid = w order by closed_at asc limit k);
    get diagnostics d = row_count;
    removed := removed + d;
    exit when d = 0;
  end loop;
  return removed;
end;
$$;

-- Removes one player's messages from a workspace's chat logs (data erase requests). Boxes left empty are deleted.
create or replace function public.chat_box_forget(w text, uid bigint) returns integer
language plpgsql as $$
declare n integer;
begin
  with t as (
    select b.id, coalesce(jsonb_agg(m) filter (where (m->>'userId')::bigint <> uid), '[]'::jsonb) as keep
      from public.chat_boxes b cross join lateral jsonb_array_elements(b.msgs) m
     where b.wid = w and b.user_ids @> array[uid]
     group by b.id)
  update public.chat_boxes b set
    msgs = t.keep,
    user_ids = array_remove(b.user_ids, uid),
    body = coalesce((select string_agg(lower(x->>'text'), E'\n') from jsonb_array_elements(t.keep) x), ''),
    names = ' ' || coalesce((select string_agg(distinct lower(x->>'name'), ' ') from jsonb_array_elements(t.keep) x), '') || ' ',
    flag_types = coalesce((select array_agg(distinct f) from jsonb_array_elements(t.keep) x, jsonb_array_elements_text(coalesce(x->'flags', '[]'::jsonb)) f), '{}'),
    bytes = octet_length(t.keep::text)
  from t where b.id = t.id;
  get diagnostics n = row_count;
  update public.chat_boxes set flagged = false where wid = w and flagged and cardinality(flag_types) = 0;
  delete from public.chat_boxes where wid = w and jsonb_array_length(msgs) = 0;
  return n;
end;
$$;

revoke all on function public.chat_box_forget(text, bigint) from public, anon, authenticated;
grant execute on function public.chat_box_forget(text, bigint) to service_role;
revoke all on function public.chat_box_usage(text) from public, anon, authenticated;
revoke all on function public.chat_box_trim(text, integer, bigint) from public, anon, authenticated;
grant execute on function public.chat_box_usage(text) to service_role;
grant execute on function public.chat_box_trim(text, integer, bigint) to service_role;

-- ===== Added in Sentinel 5.6 (admin console). Safe to run again. =====

-- Problems the site admin should know about: failed Roblox calls, failed Discord webhooks, sync errors, rate limits.
create table if not exists public.panel_events (
  id   bigserial primary key,
  at   timestamptz not null default now(),
  wid  text not null default '',
  kind text not null,
  msg  text not null default ''
);
create index if not exists panel_events_at on public.panel_events (at desc);
alter table public.panel_events enable row level security;
revoke all on public.panel_events from anon, authenticated;

-- Storage used per workspace (the stored rows, and the chat logs).
create or replace function public.panel_usage() returns table (wid text, n bigint, bytes bigint)
language sql stable as $$
  select substring(key from 2 for 12), count(*), coalesce(sum(octet_length(value::text)), 0)
    from public.panel_kv where key ~ '^w[a-f0-9]{12}:' group by 1
$$;
create or replace function public.chat_box_usage_all() returns table (wid text, n bigint, bytes bigint)
language sql stable as $$ select wid, count(*), coalesce(sum(bytes), 0) from public.chat_boxes group by wid $$;
revoke all on function public.panel_usage() from public, anon, authenticated;
revoke all on function public.chat_box_usage_all() from public, anon, authenticated;
grant execute on function public.panel_usage() to service_role;
grant execute on function public.chat_box_usage_all() to service_role;

-- ===== Added in Sentinel 6.8 (replays). Safe to run again: it only creates what is missing. =====

-- Replays: a short top-down recording of one game server, saved only when something happens (a report, a moderation
-- action, a chat alert, an exploit flag, or staff asking). Row seq 0 is the header; rows 1 and up hold the clip,
-- deflate-compressed and base64-encoded by the website. Evidence copies have evidence = true and a later keep_until.
create table if not exists public.replays (
  id          text not null,                -- XXXXXXXXX-XXXXXXXX
  seq         integer not null,
  wid         text not null,
  server      text not null default '',     -- short game server id
  started_at  timestamptz,                  -- header row only
  ended_at    timestamptz,                  -- header row only
  trigger     jsonb not null default '[]',  -- header row only: what made it save
  user_ids    bigint[] not null default '{}',
  data        text not null default '',
  bytes       integer not null default 0,
  keep_until  timestamptz not null,
  evidence    boolean not null default false,
  created_at  timestamptz not null default now(),
  primary key (id, seq)
);
create index if not exists replays_wid_time on public.replays (wid, started_at desc) where seq = 0;
create index if not exists replays_users on public.replays using gin (user_ids);
create index if not exists replays_keep on public.replays (keep_until);
alter table public.replays enable row level security;
revoke all on public.replays from anon, authenticated;

-- Replay storage per workspace, and for every workspace (admin console).
create or replace function public.replay_usage(w text) returns table (n bigint, bytes bigint)
language sql stable as $$ select count(distinct id), coalesce(sum(bytes), 0) from public.replays where wid = w $$;
create or replace function public.replay_usage_all() returns table (wid text, n bigint, bytes bigint)
language sql stable as $$ select wid, count(distinct id), coalesce(sum(bytes), 0) from public.replays group by wid $$;
revoke all on function public.replay_usage(text) from public, anon, authenticated;
revoke all on function public.replay_usage_all() from public, anon, authenticated;
grant execute on function public.replay_usage(text) to service_role;
grant execute on function public.replay_usage_all() to service_role;
