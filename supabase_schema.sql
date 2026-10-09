-- LX3 Line Monitor — Supabase schema
-- Run this in your Supabase project's SQL Editor (Database > SQL Editor > Newa query).
-- One row per VIN holds everything the web app reads/writes live: the VQ
-- checklist, the Body/Paint/TCF-out taps, and the issue log for that unit.
--
-- Access model: the whole dashboard needs a signed-in account, both to READ
-- and to WRITE. Only accounts you create yourself (Supabase dashboard >
-- Authentication > Users > Add user — there is no public sign-up form in
-- the app) can sign in. Every account also has a role — see the
-- "Account roles" section below — that decides whether it can write at all
-- and whether it can manage other accounts' roles.

-- =====================================================================
-- Account roles — admin / editor / viewer. A row here is created
-- automatically (via the trigger below) the moment you add a new account
-- in Authentication > Users, defaulting to 'viewer'. Everyone can read
-- their own role; only an admin can read everyone's and change anyone's.
--
-- BOOTSTRAP STEP (one-time, after running this whole script): the account
-- that should be the first admin must already exist in Authentication >
-- Users, then in the SQL Editor run the upsert below. Use an upsert rather
-- than a plain update — an account created (or first signed in) before this
-- script ran won't have a user_roles row yet, so update alone would silently
-- do nothing:
--   insert into public.user_roles (user_id, email, role)
--   select id, email, 'admin' from auth.users where email = 'umer.naeem@hyundai-nishat.com'
--   on conflict (user_id) do update set role = 'admin';
-- After that, manage everyone else's role from the dashboard's "Manage
-- users" panel instead of SQL.
-- =====================================================================

create table if not exists public.user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'viewer' check (role in ('admin','editor','viewer')),
  -- A toggle, not a role: any existing account (whatever its role) can be
  -- separately granted the ability to flag/unflag units as Advance Posted
  -- and set their secondary status/date (see advance_posted_units below),
  -- without being given general write access (uploads, checklist taps,
  -- issues) the way editor/admin have. Admins always have this regardless
  -- of the flag's value (see can_manage_advance_posted below).
  advance_posted_access boolean not null default false,
  updated_at timestamptz not null default now()
);
alter table public.user_roles add column if not exists advance_posted_access boolean not null default false;
alter table public.user_roles drop constraint if exists user_roles_role_check;
alter table public.user_roles add constraint user_roles_role_check check (role in ('admin','editor','viewer'));
alter table public.user_roles enable row level security;

-- security definer so this can check user_roles without the calling
-- policy's own RLS recursing into itself. search_path is locked to empty
-- (both functions fully-qualify every reference already) so a SECURITY
-- DEFINER call can't be hijacked by an object shadowed earlier in some
-- caller's search_path. EXECUTE is revoked from PUBLIC/anon and re-granted
-- only to `authenticated` — RLS policies evaluate as the querying role, so
-- authenticated still needs it, but there's no reason for an anonymous
-- (unauthenticated) request to be able to probe either function directly.
create or replace function public.is_admin(uid uuid) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists(select 1 from public.user_roles where user_id = uid and role = 'admin');
$$;
create or replace function public.has_write_access(uid uuid) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists(select 1 from public.user_roles where user_id = uid and role in ('admin','editor'));
$$;
-- Admin, or any account with the advance_posted_access toggle on — see
-- advance_posted_units below for why this is narrower than has_write_access.
create or replace function public.can_manage_advance_posted(uid uuid) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists(select 1 from public.user_roles where user_id = uid and (role = 'admin' or advance_posted_access));
$$;
revoke execute on function public.is_admin(uuid) from public;
revoke execute on function public.has_write_access(uuid) from public;
revoke execute on function public.can_manage_advance_posted(uuid) from public;
grant execute on function public.is_admin(uuid) to authenticated;
grant execute on function public.has_write_access(uuid) to authenticated;
grant execute on function public.can_manage_advance_posted(uuid) to authenticated;

-- (select auth.uid()) rather than a bare auth.uid() — lets Postgres evaluate
-- it once per query (initplan) instead of once per row; same reasoning
-- applies to every (select auth.<fn>()) below.
drop policy if exists "roles_read" on public.user_roles;
create policy "roles_read" on public.user_roles
  for select using ((select auth.uid()) = user_id or public.is_admin((select auth.uid())));
drop policy if exists "roles_insert" on public.user_roles;
create policy "roles_insert" on public.user_roles
  for insert with check ((select auth.uid()) = user_id or public.is_admin((select auth.uid())));
drop policy if exists "roles_update" on public.user_roles;
create policy "roles_update" on public.user_roles
  for update using (public.is_admin((select auth.uid()))) with check (public.is_admin((select auth.uid())));

-- Auto-provision a default 'viewer' row for every new account (created in
-- Authentication > Users) the moment it exists — no client action needed.
-- Trigger-only: nothing should ever call this directly via RPC, so EXECUTE
-- is revoked from every role below (a trigger still fires regardless of
-- grants on the function itself — it runs as the function's owner).
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.user_roles (user_id, email, role)
  values (new.id, new.email, 'viewer')
  on conflict (user_id) do nothing;
  return new;
end;
$$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();
revoke execute on function public.handle_new_user() from public;

-- Backfill: the trigger above only fires for accounts created from now on.
-- This catches every account that already existed before this script ran,
-- giving each a default 'viewer' row so it shows up in "Manage users" too.
-- Safe to re-run — on conflict skips anyone who already has a row.
insert into public.user_roles (user_id, email, role)
select id, email, 'viewer' from auth.users
on conflict (user_id) do nothing;

create table if not exists public.units_data (
  vin text primary key,
  checklist_items jsonb not null default '{}'::jsonb,
  checklist_dates jsonb not null default '{}'::jsonb,
  checklist_counts jsonb not null default '{}'::jsonb, -- how many times each step has been ticked on (off->on transitions), so a step re-marked complete after being un-ticked shows a repeat count
  issues jsonb not null default '[]'::jsonb,
  body_out date,
  paint_out date,
  tcf_out date,
  updated_at timestamptz not null default now()
);

alter table public.units_data add column if not exists checklist_counts jsonb not null default '{}'::jsonb;

alter table public.units_data enable row level security;

-- Only signed-in users can read.
drop policy if exists "public_read" on public.units_data;
drop policy if exists "authenticated_read" on public.units_data;
create policy "authenticated_read" on public.units_data
  for select using ((select auth.role()) = 'authenticated');

-- Only editor/admin accounts can write — a signed-in viewer can read but not edit.
drop policy if exists "public_write" on public.units_data;
drop policy if exists "authenticated_write" on public.units_data;
create policy "authenticated_write" on public.units_data
  for insert with check (public.has_write_access((select auth.uid())));

drop policy if exists "public_update" on public.units_data;
drop policy if exists "authenticated_update" on public.units_data;
create policy "authenticated_update" on public.units_data
  for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));

-- Turn on realtime change broadcasts for this table (Database > Replication
-- in the dashboard does the same thing — this is the SQL equivalent). Guarded
-- so re-running this whole script is always safe, even after it already ran.
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'units_data'
  ) then
    alter publication supabase_realtime add table public.units_data;
  end if;
end $$;

-- =====================================================================
-- Uploaded source data — "LX3 Data.xlsx" (production roster) and
-- "LX3 defect report.xlsx" (VIN-wise defects), replaced in full each time
-- someone with an account uploads a new file from the dashboard's
-- "Upload data" panel. Same access model as units_data above: signed-in
-- accounts only, both to read and to write.
-- =====================================================================

create table if not exists public.production_rows (
  batch text primary key,
  vin text,
  color_code text,
  color_desc text,
  status_code text,
  body_start int,      -- Excel date serials (matches the app's xl() helper) —
  body_fin int,        -- not SQL dates, so no timezone conversion surprises.
  paint_start int,
  paint_fin int,
  tcf_start int,
  tcf_fin int,
  basic_insp int,
  actual_insp int,      -- Inspection In
  act_fin_insp int,     -- Inspection Out
  ustk int,
  updated_at timestamptz not null default now()
);
-- Safe to re-run against a table created before these three columns existed.
alter table public.production_rows add column if not exists body_start int;
alter table public.production_rows add column if not exists paint_start int;
alter table public.production_rows add column if not exists tcf_start int;
alter table public.production_rows enable row level security;
drop policy if exists "production_read" on public.production_rows;
create policy "production_read" on public.production_rows for select using ((select auth.role()) = 'authenticated');
drop policy if exists "production_write" on public.production_rows;
create policy "production_write" on public.production_rows for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "production_update" on public.production_rows;
create policy "production_update" on public.production_rows for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));
drop policy if exists "production_delete" on public.production_rows;
create policy "production_delete" on public.production_rows for delete using (public.has_write_access((select auth.uid())));

create table if not exists public.defect_rows (
  id bigint generated always as identity primary key,
  vin text not null,             -- 6-digit VIN suffix, e.g. "900094"
  station text,                  -- inspection station ("Process Name" in the source file)
  department text,               -- Body Shop / Paint Shop / TCF / Plastic Paint Shop; null on older rows logged before this field was used
  description text,              -- null when has_defect is false (a clean inspection pass)
  defect_serial int,             -- Excel date serial
  has_defect boolean not null default false,
  updated_at timestamptz not null default now()
);
-- Safe to re-run against a table created before this column existed.
alter table public.defect_rows add column if not exists department text;
alter table public.defect_rows enable row level security;
drop policy if exists "defect_read" on public.defect_rows;
create policy "defect_read" on public.defect_rows for select using ((select auth.role()) = 'authenticated');
drop policy if exists "defect_write" on public.defect_rows;
create policy "defect_write" on public.defect_rows for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "defect_update" on public.defect_rows;
create policy "defect_update" on public.defect_rows for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));
drop policy if exists "defect_delete" on public.defect_rows;
create policy "defect_delete" on public.defect_rows for delete using (public.has_write_access((select auth.uid())));

-- =====================================================================
-- Manual defect sheet — a hand-recorded defect log (separate from the
-- VIN-wise defect report above), uploaded from the same "Upload data"
-- panel's third file picker. Adds two things the other defect report
-- doesn't carry: a severity rating per defect, and the vehicle's current
-- physical location/status note (e.g. "Q-UP REPAIR", "VQ LINE INSPECTION").
-- Same access model: signed-in to read, editor/admin to write.
-- =====================================================================

create table if not exists public.manual_defects (
  id bigint generated always as identity primary key,
  vin text not null,             -- 6-digit VIN suffix, e.g. "900094"
  station text,                  -- inspection station ("Process Name" in the source file)
  department text,               -- BS/PS/TCF/PPS, spelled out (Body Shop, Paint Shop, ...)
  description text,              -- null when has_defect is false (a clean inspection pass)
  severity text check (severity in ('Low','Medium','Major')),
  defect_serial int,             -- Excel date serial
  has_defect boolean not null default false,
  updated_at timestamptz not null default now()
);
alter table public.manual_defects enable row level security;
drop policy if exists "manual_defects_read" on public.manual_defects;
create policy "manual_defects_read" on public.manual_defects for select using ((select auth.role()) = 'authenticated');
drop policy if exists "manual_defects_write" on public.manual_defects;
create policy "manual_defects_write" on public.manual_defects for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "manual_defects_update" on public.manual_defects;
create policy "manual_defects_update" on public.manual_defects for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));
drop policy if exists "manual_defects_delete" on public.manual_defects;
create policy "manual_defects_delete" on public.manual_defects for delete using (public.has_write_access((select auth.uid())));

-- One row per VIN: wherever the manual sheet's "LOCATION" column last said
-- that vehicle currently is, and when. Replaced in full on each upload,
-- same as manual_defects above (both come from the same file).
create table if not exists public.manual_vehicle_status (
  vin text primary key,
  location text,
  location_note text,            -- the raw text after the location, usually a timestamp like "25-SEP-26 (20:45)"
  updated_at timestamptz not null default now()
);
alter table public.manual_vehicle_status enable row level security;
drop policy if exists "manual_status_read" on public.manual_vehicle_status;
create policy "manual_status_read" on public.manual_vehicle_status for select using ((select auth.role()) = 'authenticated');
drop policy if exists "manual_status_write" on public.manual_vehicle_status;
create policy "manual_status_write" on public.manual_vehicle_status for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "manual_status_update" on public.manual_vehicle_status;
create policy "manual_status_update" on public.manual_vehicle_status for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));
drop policy if exists "manual_status_delete" on public.manual_vehicle_status;
create policy "manual_status_delete" on public.manual_vehicle_status for delete using (public.has_write_access((select auth.uid())));

-- =====================================================================
-- Storage bucket for photos attached to Issues & remarks on a VIN card.
-- Public read (so the <img>/link just works for anyone viewing the
-- dashboard), editor/admin write — same access model as everything else.
-- =====================================================================
insert into storage.buckets (id, name, public)
values ('issue-photos', 'issue-photos', true)
on conflict (id) do nothing;

drop policy if exists "issue_photos_read" on storage.objects;
create policy "issue_photos_read" on storage.objects
  for select using (bucket_id = 'issue-photos');
drop policy if exists "issue_photos_write" on storage.objects;
create policy "issue_photos_write" on storage.objects
  for insert with check (bucket_id = 'issue-photos' and public.has_write_access(auth.uid()));
drop policy if exists "issue_photos_delete" on storage.objects;
create policy "issue_photos_delete" on storage.objects
  for delete using (bucket_id = 'issue-photos' and public.has_write_access(auth.uid()));

-- =====================================================================
-- Storage bucket holding the raw .xlsx of the most recent Production Data
-- Upload (overwritten each time someone uploads a new one, mirroring how
-- production_rows itself is fully replaced). Private bucket — unlike
-- issue-photos, only admins may read/download it; editors can still
-- upload (same as they can write production_rows), which also means
-- editors need delete rights here (the app does an explicit remove, then
-- insert, to replace the file — see note below on why not upsert).
-- =====================================================================
insert into storage.buckets (id, name, public)
values ('production-uploads', 'production-uploads', false)
on conflict (id) do nothing;

drop policy if exists "production_uploads_read" on storage.objects;
create policy "production_uploads_read" on storage.objects
  for select using (bucket_id = 'production-uploads' and public.is_admin((select auth.uid())));
drop policy if exists "production_uploads_write" on storage.objects;
create policy "production_uploads_write" on storage.objects
  for insert with check (bucket_id = 'production-uploads' and public.has_write_access((select auth.uid())));
-- Not actually exercised by the app (it does remove+insert, not upsert —
-- see the client-side comment on why), but kept complete/symmetric in
-- case anything ever does update an object in place.
drop policy if exists "production_uploads_update" on storage.objects;
create policy "production_uploads_update" on storage.objects
  for update using (bucket_id = 'production-uploads' and public.has_write_access((select auth.uid())))
  with check (bucket_id = 'production-uploads' and public.has_write_access((select auth.uid())));
drop policy if exists "production_uploads_delete" on storage.objects;
create policy "production_uploads_delete" on storage.objects
  for delete using (bucket_id = 'production-uploads' and public.has_write_access((select auth.uid())));

-- =====================================================================
-- Activity log — powers the "Activity Log" tab: who did what and when
-- (data uploads/clears, VIN card checklist/milestone taps, issue
-- add/edit/delete, role changes, account creation). Append-only from most
-- accounts' point of view — everyone signed in can read it, only accounts
-- with write access can add entries (matches who can actually do the
-- things being logged), and only admins can delete entries.
-- =====================================================================
create table if not exists public.activity_log (
  id bigint generated always as identity primary key,
  actor text,             -- the signed-in account's email
  action text not null,   -- e.g. 'production_upload', 'checklist_tap', 'issue_add'
  detail text,            -- human-readable one-liner
  vin text,                -- 6-digit VIN suffix, when the action is VIN-scoped
  created_at timestamptz not null default now()
);
alter table public.activity_log enable row level security;
drop policy if exists "activity_log_read" on public.activity_log;
create policy "activity_log_read" on public.activity_log for select using ((select auth.role()) = 'authenticated');
drop policy if exists "activity_log_write" on public.activity_log;
create policy "activity_log_write" on public.activity_log for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "activity_log_delete" on public.activity_log;
create policy "activity_log_delete" on public.activity_log for delete using (public.is_admin((select auth.uid())));

-- =====================================================================
-- Advance Posted units — month-end, production bulk-advance-posts WIP
-- units in SAP for invoicing, which makes the uploaded production Excel
-- show them as Sold/BU Stock even though they're physically still
-- mid-process. A unit flagged here has its SAP status overridden in the
-- app by this manually-tracked "secondary status" (one of the regular
-- stage codes — Body/Paint/TCF in/out, Inspection in/out) until someone
-- un-flags it. Flagging/unflagging and setting the secondary status are
-- gated on can_manage_advance_posted — admin, or any account with the
-- advance_posted_access toggle on, NOT the usual editor write access —
-- since this is a distinct, more sensitive workflow than ordinary data
-- entry.
-- Everyone signed in can still READ it (it drives what every viewer sees
-- on the Units table/VIN card).
-- =====================================================================
create table if not exists public.advance_posted_units (
  vin text primary key,
  secondary_status text,       -- a code from the app's stage list (Tester Line/Q-UP/Repair/etc.) that production sets to track where the unit really is
  flagged_by text,
  flagged_at timestamptz not null default now(),
  status_set_by text,
  status_set_at timestamptz
);
alter table public.advance_posted_units enable row level security;
drop policy if exists "advance_posted_read" on public.advance_posted_units;
create policy "advance_posted_read" on public.advance_posted_units for select using ((select auth.role()) = 'authenticated');
drop policy if exists "advance_posted_write" on public.advance_posted_units;
create policy "advance_posted_write" on public.advance_posted_units for insert with check (public.can_manage_advance_posted((select auth.uid())));
drop policy if exists "advance_posted_update" on public.advance_posted_units;
create policy "advance_posted_update" on public.advance_posted_units for update using (public.can_manage_advance_posted((select auth.uid()))) with check (public.can_manage_advance_posted((select auth.uid())));
drop policy if exists "advance_posted_delete" on public.advance_posted_units;
create policy "advance_posted_delete" on public.advance_posted_units for delete using (public.can_manage_advance_posted((select auth.uid())));

-- Full movement history, not just a single current status — production
-- planning can log as many dated location changes as they want, and the
-- VIN card's Overview timeline prefers these dates over SAP's when an
-- advance-posted unit has an entry for that milestone. The "current"
-- secondary status shown everywhere else is just the entry with the
-- latest moved_at (ties broken by created_at), computed client-side.
create table if not exists public.advance_posted_movements (
  id bigint generated always as identity primary key,
  vin text not null references public.advance_posted_units(vin) on delete cascade,
  status_code text not null,
  moved_at date not null,
  set_by text,
  created_at timestamptz not null default now()
);
create index if not exists advance_posted_movements_vin_idx on public.advance_posted_movements(vin);
alter table public.advance_posted_movements enable row level security;
drop policy if exists "advance_posted_movements_read" on public.advance_posted_movements;
create policy "advance_posted_movements_read" on public.advance_posted_movements for select using ((select auth.role()) = 'authenticated');
drop policy if exists "advance_posted_movements_write" on public.advance_posted_movements;
create policy "advance_posted_movements_write" on public.advance_posted_movements for insert with check (public.can_manage_advance_posted((select auth.uid())));
drop policy if exists "advance_posted_movements_update" on public.advance_posted_movements;
create policy "advance_posted_movements_update" on public.advance_posted_movements for update using (public.can_manage_advance_posted((select auth.uid()))) with check (public.can_manage_advance_posted((select auth.uid())));
drop policy if exists "advance_posted_movements_delete" on public.advance_posted_movements;
create policy "advance_posted_movements_delete" on public.advance_posted_movements for delete using (public.can_manage_advance_posted((select auth.uid())));

-- =====================================================================
-- Defect annotations — quality root-cause tracking for recurring defect
-- TYPES (e.g. "Water Leakage Due To Tailgate Weather Strip NPF"), not
-- individual per-VIN occurrences. Keyed by the normalized defect
-- description text (trim+uppercase, matching the same grouping key the
-- "Most frequent defects" table already uses) rather than a row ID from
-- defect_rows/manual_defects, since those tables are fully replaced on
-- every upload — a row-ID foreign key would break on the next upload,
-- but the description text is stable across re-uploads of the same
-- recurring defect. Same access model as everything else: signed-in to
-- read, editor/admin to write.
-- =====================================================================
create table if not exists public.defect_annotations (
  id bigint generated always as identity primary key,
  description_key text not null unique,
  description text,          -- original-case example text, for display
  photo_url text,            -- legacy single-photo column, superseded by photo_urls
  photo_urls text[] not null default '{}',
  is_critical boolean not null default false,  -- flagged for management attention
  critical_reason text,
  root_cause text,
  corrective_action text,
  status text not null default 'open' check (status in ('open','closed')),
  updated_by text,
  updated_at timestamptz not null default now()
);
alter table public.defect_annotations enable row level security;
drop policy if exists "defect_annotations_read" on public.defect_annotations;
create policy "defect_annotations_read" on public.defect_annotations for select using ((select auth.role()) = 'authenticated');
drop policy if exists "defect_annotations_write" on public.defect_annotations;
create policy "defect_annotations_write" on public.defect_annotations for insert with check (public.has_write_access((select auth.uid())));
drop policy if exists "defect_annotations_update" on public.defect_annotations;
create policy "defect_annotations_update" on public.defect_annotations for update using (public.has_write_access((select auth.uid()))) with check (public.has_write_access((select auth.uid())));
drop policy if exists "defect_annotations_delete" on public.defect_annotations;
create policy "defect_annotations_delete" on public.defect_annotations for delete using (public.has_write_access((select auth.uid())));

-- Photos attached to a defect annotation. Public read (same as
-- issue-photos, so <img> just works for anyone viewing the dashboard),
-- editor/admin write.
insert into storage.buckets (id, name, public)
values ('defect-photos', 'defect-photos', true)
on conflict (id) do nothing;
drop policy if exists "defect_photos_read" on storage.objects;
create policy "defect_photos_read" on storage.objects for select using (bucket_id = 'defect-photos');
drop policy if exists "defect_photos_write" on storage.objects;
create policy "defect_photos_write" on storage.objects for insert with check (bucket_id = 'defect-photos' and public.has_write_access((select auth.uid())));
drop policy if exists "defect_photos_delete" on storage.objects;
create policy "defect_photos_delete" on storage.objects for delete using (bucket_id = 'defect-photos' and public.has_write_access((select auth.uid())));
