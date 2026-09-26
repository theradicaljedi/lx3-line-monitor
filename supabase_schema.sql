-- LX3 Line Monitor — Supabase schema
-- Run this once in your Supabase project's SQL Editor (Database > SQL Editor > New query).
-- One row per VIN holds everything the web app reads/writes live: the VQ
-- checklist, the Body/Paint/TCF-out taps, and the issue log for that unit.

create table if not exists public.units_data (
  vin text primary key,
  checklist_items jsonb not null default '{}'::jsonb,
  checklist_dates jsonb not null default '{}'::jsonb,
  issues jsonb not null default '[]'::jsonb,
  body_out date,
  paint_out date,
  tcf_out date,
  updated_at timestamptz not null default now()
);

-- Row Level Security: on, with public (no-login) read/write policies, matching
-- "anyone with the link" access. Anyone who has the URL and anon key can write
-- rows — there is no per-user auth in this setup. If you later want to
-- restrict writes, replace the two "public_*" policies below with ones that
-- check `auth.role() = 'authenticated'` (requires adding Supabase Auth to the
-- app) instead of `true`.
alter table public.units_data enable row level security;

drop policy if exists "public_read" on public.units_data;
create policy "public_read" on public.units_data
  for select using (true);

drop policy if exists "public_write" on public.units_data;
create policy "public_write" on public.units_data
  for insert with check (true);

drop policy if exists "public_update" on public.units_data;
create policy "public_update" on public.units_data
  for update using (true) with check (true);

-- Turn on realtime change broadcasts for this table (Database > Replication
-- in the dashboard does the same thing — this is the SQL equivalent).
alter publication supabase_realtime add table public.units_data;
