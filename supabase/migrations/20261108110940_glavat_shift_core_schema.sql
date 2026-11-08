
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default 'Сотрудник',
  role text not null default 'employee' check (role in ('owner','admin','employee')),
  is_active boolean not null default true,
  color text not null default '#64748b',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.shifts (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.profiles(id) on delete restrict,
  shift_date date not null,
  start_time time not null,
  end_time time not null,
  note text not null default '',
  status text not null default 'draft' check (status in ('draft','published','cancelled')),
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint shift_time_not_equal check (start_time <> end_time)
);
create index if not exists shifts_date_idx on public.shifts(shift_date);
create index if not exists shifts_employee_date_idx on public.shifts(employee_id, shift_date);

create table if not exists public.shift_requests (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.profiles(id) on delete cascade,
  request_type text not null check (request_type in ('day_off','replacement','swap','time_change','other')),
  requested_date date not null,
  target_employee_id uuid references public.profiles(id) on delete set null,
  shift_id uuid references public.shifts(id) on delete set null,
  details text not null default '',
  status text not null default 'pending' check (status in ('pending','approved','rejected','cancelled')),
  reviewer_comment text not null default '',
  reviewed_by uuid references public.profiles(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists shift_requests_status_idx on public.shift_requests(status, created_at desc);

create table if not exists public.invitations (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  role text not null default 'employee' check (role in ('admin','employee')),
  token_hash text not null unique,
  invited_by uuid not null references public.profiles(id) on delete restrict,
  expires_at timestamptz not null default (now() + interval '7 days'),
  accepted_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null,
  entity_type text not null,
  entity_id uuid,
  before_data jsonb,
  after_data jsonb,
  created_at timestamptz not null default now()
);
create index if not exists audit_log_created_idx on public.audit_log(created_at desc);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  body text not null default '',
  kind text not null default 'info',
  entity_type text,
  entity_id uuid,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_created_idx on public.notifications(user_id, created_at desc);

create table if not exists public.schedule_publications (
  id uuid primary key default gen_random_uuid(),
  week_start date not null,
  published_by uuid references public.profiles(id) on delete set null,
  published_at timestamptz not null default now(),
  note text not null default '',
  unique(week_start)
);

create or replace function public.is_manager()
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.is_active and p.role in ('owner','admin')
  );
$$;

create or replace function public.is_owner()
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.is_active and p.role = 'owner'
  );
$$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  assigned_role text := 'employee';
  invite public.invitations%rowtype;
  supplied_token text;
begin
  supplied_token := new.raw_user_meta_data ->> 'invite_token';
  if supplied_token is not null then
    select * into invite from public.invitations
      where token_hash = encode(extensions.digest(supplied_token, 'sha256'), 'hex')
        and lower(email) = lower(new.email)
        and accepted_at is null and expires_at > now()
      for update;
    if found then
      assigned_role := invite.role;
      update public.invitations set accepted_at = now() where id = invite.id;
    end if;
  end if;

  -- Atomic first-user bootstrap: the first account becomes the workspace owner.
  perform pg_advisory_xact_lock(hashtext('glavat_shift_first_owner'));
  if not exists (select 1 from public.profiles where role = 'owner') then
    assigned_role := 'owner';
  end if;

  insert into public.profiles(id, full_name, role)
  values (new.id, coalesce(nullif(new.raw_user_meta_data ->> 'full_name',''), split_part(new.email,'@',1), 'Сотрудник'), assigned_role)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.audit_shift_changes()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  actor uuid := coalesce((select auth.uid()), new.created_by, old.updated_by);
  entity uuid := coalesce(new.id, old.id);
begin
  if tg_op = 'INSERT' then
    insert into public.audit_log(actor_id, action, entity_type, entity_id, after_data)
    values (actor, 'shift.created', 'shift', new.id, to_jsonb(new));
    return new;
  elsif tg_op = 'UPDATE' then
    insert into public.audit_log(actor_id, action, entity_type, entity_id, before_data, after_data)
    values (actor, 'shift.updated', 'shift', new.id, to_jsonb(old), to_jsonb(new));
    return new;
  elsif tg_op = 'DELETE' then
    insert into public.audit_log(actor_id, action, entity_type, entity_id, before_data)
    values (actor, 'shift.deleted', 'shift', old.id, to_jsonb(old));
    return old;
  end if;
  return null;
end;
$$;
drop trigger if exists shifts_audit_trigger on public.shifts;
create trigger shifts_audit_trigger after insert or update or delete on public.shifts
for each row execute procedure public.audit_shift_changes();

create or replace function public.notify_shift_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  recipient uuid;
  msg text;
  ttl text;
begin
  if tg_op = 'INSERT' then
    ttl := 'Новая смена';
    msg := 'В расписании появилась смена на ' || to_char(new.shift_date,'DD.MM.YYYY') || ' с ' || left(new.start_time::text,5) || ' до ' || left(new.end_time::text,5) || '.';
    recipient := new.employee_id;
  elsif tg_op = 'UPDATE' then
    ttl := 'Изменение смены';
    msg := 'Изменена ваша смена на ' || to_char(new.shift_date,'DD.MM.YYYY') || '.';
    recipient := new.employee_id;
  else
    ttl := 'Смена удалена';
    msg := 'Ваша смена на ' || to_char(old.shift_date,'DD.MM.YYYY') || ' удалена.';
    recipient := old.employee_id;
  end if;
  if recipient is not null and (tg_op <> 'UPDATE' or row(new.shift_date,new.start_time,new.end_time,new.employee_id,new.status) is distinct from row(old.shift_date,old.start_time,old.end_time,old.employee_id,old.status)) then
    insert into public.notifications(user_id,title,body,kind,entity_type,entity_id)
    values(recipient,ttl,msg,'schedule','shift',coalesce(new.id,old.id));
  end if;
  return coalesce(new,old);
end;
$$;
drop trigger if exists shifts_notify_trigger on public.shifts;
create trigger shifts_notify_trigger after insert or update or delete on public.shifts
for each row execute procedure public.notify_shift_change();

create or replace function public.notify_request_review()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if old.status = 'pending' and new.status in ('approved','rejected') then
    insert into public.audit_log(actor_id,action,entity_type,entity_id,before_data,after_data)
    values((select auth.uid()), case when new.status='approved' then 'request.approved' else 'request.rejected' end, 'request', new.id, to_jsonb(old), to_jsonb(new));
    insert into public.notifications(user_id,title,body,kind,entity_type,entity_id)
    values(new.employee_id,
      case when new.status='approved' then 'Заявка одобрена' else 'Заявка отклонена' end,
      coalesce(nullif(new.reviewer_comment,''),'Администратор рассмотрел вашу заявку.'),
      'request','request',new.id);
  end if;
  return new;
end;
$$;
drop trigger if exists request_review_notify_trigger on public.shift_requests;
create trigger request_review_notify_trigger after update on public.shift_requests
for each row execute procedure public.notify_request_review();

alter table public.profiles enable row level security;
alter table public.shifts enable row level security;
alter table public.shift_requests enable row level security;
alter table public.invitations enable row level security;
alter table public.audit_log enable row level security;
alter table public.notifications enable row level security;
alter table public.schedule_publications enable row level security;

drop policy if exists "Profiles visible to authenticated team" on public.profiles;
drop policy if exists "Users can create own profile" on public.profiles;
drop policy if exists "Admins update profiles" on public.profiles;
create policy "Active team can read profiles" on public.profiles for select to authenticated using (
  exists(select 1 from public.profiles me where me.id=(select auth.uid()) and me.is_active)
);
create policy "Users update own display name" on public.profiles for update to authenticated
using (id=(select auth.uid())) with check (id=(select auth.uid()) and role=(select role from public.profiles p where p.id=(select auth.uid())));
create policy "Managers update team profiles" on public.profiles for update to authenticated
using (public.is_manager()) with check (public.is_manager());

drop policy if exists "Team can read shifts" on public.shifts;
drop policy if exists "Admins manage shifts" on public.shifts;
create policy "Active team read shifts" on public.shifts for select to authenticated
using (exists(select 1 from public.profiles me where me.id=(select auth.uid()) and me.is_active) and (status='published' or public.is_manager() or employee_id=(select auth.uid())));
create policy "Managers insert shifts" on public.shifts for insert to authenticated
with check (public.is_manager() and created_by=(select auth.uid()));
create policy "Managers update shifts" on public.shifts for update to authenticated
using (public.is_manager()) with check (public.is_manager());
create policy "Managers delete shifts" on public.shifts for delete to authenticated using (public.is_manager());

drop policy if exists "Employees read own requests, admins read all" on public.shift_requests;
drop policy if exists "Employees create own requests" on public.shift_requests;
drop policy if exists "Admins review requests" on public.shift_requests;
create policy "Read own or all requests" on public.shift_requests for select to authenticated
using (employee_id=(select auth.uid()) or public.is_manager());
create policy "Create own requests" on public.shift_requests for insert to authenticated
with check (employee_id=(select auth.uid()) and status='pending');
create policy "Managers review requests" on public.shift_requests for update to authenticated
using (public.is_manager()) with check (public.is_manager());

create policy "Managers read invitations" on public.invitations for select to authenticated using (public.is_manager());
create policy "Managers manage invitations" on public.invitations for all to authenticated
using (public.is_manager()) with check (public.is_manager() and invited_by=(select auth.uid()));
create policy "Managers read audit log" on public.audit_log for select to authenticated using (public.is_manager());
create policy "Users read own notifications" on public.notifications for select to authenticated using (user_id=(select auth.uid()) or public.is_manager());
create policy "Users update own notifications" on public.notifications for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
create policy "Team read publications" on public.schedule_publications for select to authenticated using (exists(select 1 from public.profiles me where me.id=(select auth.uid()) and me.is_active));
create policy "Managers manage publications" on public.schedule_publications for all to authenticated using (public.is_manager()) with check (public.is_manager());

create or replace function public.create_team_invitation(p_email text, p_role text default 'employee')
returns text language plpgsql security definer set search_path = ''
as $$
declare
  raw_token text := encode(extensions.gen_random_bytes(32),'hex');
begin
  if not public.is_manager() then raise exception 'Недостаточно прав'; end if;
  if p_role not in ('admin','employee') then raise exception 'Недопустимая роль'; end if;
  insert into public.invitations(email,role,token_hash,invited_by)
  values(lower(trim(p_email)),p_role,encode(extensions.digest(raw_token,'sha256'),'hex'),(select auth.uid()));
  return raw_token;
end;
$$;
revoke all on function public.create_team_invitation(text,text) from public;
grant execute on function public.create_team_invitation(text,text) to authenticated;

create or replace function public.publish_schedule(p_week_start date, p_note text default '')
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if not public.is_manager() then raise exception 'Недостаточно прав'; end if;
  update public.shifts set status='published', updated_by=(select auth.uid()), updated_at=now()
  where shift_date between p_week_start and p_week_start + 6 and status='draft';
  insert into public.schedule_publications(week_start,published_by,note)
  values(p_week_start,(select auth.uid()),coalesce(p_note,''))
  on conflict(week_start) do update set published_by=excluded.published_by,published_at=now(),note=excluded.note;
end;
$$;
revoke all on function public.publish_schedule(date,text) from public;
grant execute on function public.publish_schedule(date,text) to authenticated;

grant usage on schema public to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.shifts to authenticated;
grant select, insert, update on public.shift_requests to authenticated;
grant select on public.invitations, public.audit_log, public.schedule_publications to authenticated;
grant select, update on public.notifications to authenticated;
grant usage, select on sequence public.audit_log_id_seq to authenticated;
