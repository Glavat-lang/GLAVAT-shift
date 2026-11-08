alter table public.profiles add column if not exists username text;

update public.profiles p
set username = lower(split_part(u.email, '@', 1))
from auth.users u
where u.id = p.id and (p.username is null or btrim(p.username) = '');

do $$
begin
  if exists (
    select 1 from public.profiles
    where username is null
       or username !~ '^[a-z0-9][a-z0-9_.-]{2,23}$'
  ) then
    raise exception 'Existing profile usernames need manual normalization before migration';
  end if;
end $$;

create unique index if not exists profiles_username_lower_uidx
on public.profiles (lower(username));

alter table public.profiles alter column username set not null;
alter table public.invitations add column if not exists username text;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $function$
declare
  assigned_role text := 'employee';
  invite public.invitations%rowtype;
  supplied_token text := new.raw_user_meta_data ->> 'invite_token';
  supplied_username text := lower(trim(coalesce(new.raw_user_meta_data ->> 'username', '')));
begin
  if supplied_username !~ '^[a-z0-9][a-z0-9_.-]{2,23}$' then
    raise exception 'Логин: 3–24 символа, латинские буквы, цифры, точка, дефис или подчёркивание';
  end if;
  perform pg_advisory_xact_lock(hashtext('glavat_shift_first_owner'));
  if exists(select 1 from public.profiles where role='owner') then
    if supplied_token is null then raise exception 'Регистрация доступна только по приглашению руководителя'; end if;
    select * into invite from public.invitations
    where token_hash=encode(extensions.digest(supplied_token,'sha256'),'hex')
      and accepted_at is null and expires_at>now()
      and lower(username)=supplied_username
    for update;
    if not found then raise exception 'Приглашение недействительно, истекло или выдано другому логину'; end if;
    assigned_role:=invite.role;
    update public.invitations set accepted_at=now() where id=invite.id;
  else
    assigned_role:='owner';
  end if;
  insert into public.profiles(id,full_name,username,role)
  values(new.id,coalesce(nullif(new.raw_user_meta_data->>'full_name',''),split_part(new.email,'@',1),'Сотрудник'),supplied_username,assigned_role)
  on conflict(id) do nothing;
  return new;
end;
$function$;

drop function public.create_team_invitation(text,text);
create function public.create_team_invitation(p_username text, p_role text default 'employee')
returns text language plpgsql security definer set search_path = ''
as $function$
declare
  raw_token text:=encode(extensions.gen_random_bytes(32),'hex');
  normalized_username text:=lower(trim(coalesce(p_username,'')));
begin
  if not public.is_manager() then raise exception 'Недостаточно прав'; end if;
  if normalized_username !~ '^[a-z0-9][a-z0-9_.-]{2,23}$' then
    raise exception 'Логин должен содержать 3–24 символа: латинские буквы, цифры, точку, дефис или подчёркивание';
  end if;
  if p_role not in ('admin','employee') then raise exception 'Недопустимая роль'; end if;
  if p_role='admin' and not public.is_owner() then raise exception 'Только владелец может приглашать администраторов'; end if;
  if exists(select 1 from public.profiles where lower(username)=normalized_username) then raise exception 'Этот логин уже зарегистрирован'; end if;
  if exists(select 1 from public.invitations where lower(username)=normalized_username and accepted_at is null and expires_at>now()) then
    raise exception 'Для этого логина уже есть действующее приглашение';
  end if;
  insert into public.invitations(email,username,role,token_hash,invited_by)
  values(normalized_username||'@login.glavat.invalid',normalized_username,p_role,encode(extensions.digest(raw_token,'sha256'),'hex'),(select auth.uid()));
  return raw_token;
end;
$function$;

create or replace function public.auth_email_for_username(p_username text)
returns text language sql security definer set search_path = '' stable
as $function$
  select u.email from public.profiles p join auth.users u on u.id=p.id
  where lower(p.username)=lower(trim(p_username)) and p.is_active=true limit 1;
$function$;
revoke all on function public.auth_email_for_username(text) from public, anon, authenticated;
grant execute on function public.auth_email_for_username(text) to service_role;