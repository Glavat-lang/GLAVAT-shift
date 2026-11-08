alter table public.profiles add column if not exists auth_email text;
update public.profiles p set auth_email=u.email from auth.users u where u.id=p.id and p.auth_email is distinct from u.email;
alter table public.profiles alter column auth_email set not null;

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
  insert into public.profiles(id,full_name,username,auth_email,role)
  values(new.id,coalesce(nullif(new.raw_user_meta_data->>'full_name',''),split_part(new.email,'@',1),'Сотрудник'),supplied_username,new.email,assigned_role)
  on conflict(id) do nothing;
  return new;
end;
$function$;

create or replace function public.auth_email_for_username(p_username text)
returns text language sql security definer set search_path = '' stable
as $function$
  select p.auth_email from public.profiles p
  where lower(p.username)=lower(trim(p_username)) and p.is_active=true limit 1;
$function$;
revoke all on function public.auth_email_for_username(text) from public, anon, authenticated;
grant execute on function public.auth_email_for_username(text) to service_role;