drop function if exists public.create_team_invitation(text,text);

create function public.create_team_invitation(p_email text, p_role text default 'employee')
returns text
language plpgsql
security definer
set search_path = ''
as $function$
declare
  raw_token text := encode(extensions.gen_random_bytes(32), 'hex');
  normalized_email text := lower(trim(coalesce(p_email, '')));
begin
  if not public.is_manager() then
    raise exception 'Недостаточно прав';
  end if;
  if normalized_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' then
    raise exception 'Укажите корректный email';
  end if;
  if p_role not in ('admin','employee') then
    raise exception 'Недопустимая роль';
  end if;
  if p_role = 'admin' and not public.is_owner() then
    raise exception 'Только владелец может приглашать администраторов';
  end if;
  if exists (
    select 1 from public.profiles
    where lower(auth_email) = normalized_email
  ) then
    raise exception 'Этот email уже зарегистрирован';
  end if;
  if exists (
    select 1 from public.invitations
    where lower(email) = normalized_email
      and accepted_at is null
      and expires_at > now()
  ) then
    raise exception 'Для этого email уже есть действующее приглашение';
  end if;
  insert into public.invitations(email, role, token_hash, invited_by)
  values (
    normalized_email,
    p_role,
    encode(extensions.digest(raw_token, 'sha256'), 'hex'),
    (select auth.uid())
  );
  return raw_token;
end;
$function$;

revoke all on function public.create_team_invitation(text,text) from public, anon;
grant execute on function public.create_team_invitation(text,text) to authenticated;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
declare
  assigned_role text := 'employee';
  invite public.invitations%rowtype;
  supplied_token text := new.raw_user_meta_data ->> 'invite_token';
  normalized_email text := lower(trim(coalesce(new.email, '')));
  generated_username text;
begin
  generated_username := lower(regexp_replace(split_part(normalized_email, '@', 1), '[^a-z0-9_.-]', '', 'g'));
  if generated_username !~ '^[a-z0-9][a-z0-9_.-]{2,23}$' then
    generated_username := 'user' || substr(replace(new.id::text, '-', ''), 1, 12);
  end if;
  if exists (select 1 from public.profiles where lower(username) = generated_username) then
    generated_username := 'u' || substr(md5(normalized_email), 1, 15);
  end if;

  perform pg_advisory_xact_lock(hashtext('glavat_shift_first_owner'));
  if exists(select 1 from public.profiles where role = 'owner') then
    if supplied_token is null then
      raise exception 'Регистрация доступна только по приглашению руководителя';
    end if;
    select * into invite
    from public.invitations
    where token_hash = encode(extensions.digest(supplied_token, 'sha256'), 'hex')
      and accepted_at is null
      and expires_at > now()
      and lower(email) = normalized_email
    for update;
    if not found then
      raise exception 'Приглашение недействительно, истекло или выдано другому email';
    end if;
    assigned_role := invite.role;
    update public.invitations set accepted_at = now() where id = invite.id;
  else
    assigned_role := 'owner';
  end if;

  insert into public.profiles(id, full_name, username, auth_email, role)
  values (
    new.id,
    coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), split_part(normalized_email, '@', 1), 'Сотрудник'),
    generated_username,
    normalized_email,
    assigned_role
  )
  on conflict(id) do nothing;
  return new;
end;
$function$;