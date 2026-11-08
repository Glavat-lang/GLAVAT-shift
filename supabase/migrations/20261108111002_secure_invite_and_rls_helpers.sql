
create or replace function public.current_user_active()
returns boolean language sql stable security definer set search_path = ''
as $$
  select exists(select 1 from public.profiles p where p.id=(select auth.uid()) and p.is_active);
$$;
create or replace function public.current_user_role()
returns text language sql stable security definer set search_path = ''
as $$
  select p.role from public.profiles p where p.id=(select auth.uid()) and p.is_active;
$$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare
  assigned_role text := 'employee';
  invite public.invitations%rowtype;
  supplied_token text := new.raw_user_meta_data ->> 'invite_token';
begin
  perform pg_advisory_xact_lock(hashtext('glavat_shift_first_owner'));
  if exists(select 1 from public.profiles where role='owner') then
    if supplied_token is null then raise exception 'Регистрация доступна только по приглашению'; end if;
    select * into invite from public.invitations
      where token_hash=encode(extensions.digest(supplied_token,'sha256'),'hex')
        and lower(email)=lower(new.email)
        and accepted_at is null and expires_at>now()
      for update;
    if not found then raise exception 'Приглашение недействительно или истекло'; end if;
    assigned_role := invite.role;
    update public.invitations set accepted_at=now() where id=invite.id;
  else
    assigned_role := 'owner';
  end if;
  insert into public.profiles(id,full_name,role)
  values(new.id,coalesce(nullif(new.raw_user_meta_data->>'full_name',''),split_part(new.email,'@',1),'Сотрудник'),assigned_role)
  on conflict(id) do nothing;
  return new;
end;
$$;

drop policy if exists "Active team can read profiles" on public.profiles;
drop policy if exists "Users update own display name" on public.profiles;
drop policy if exists "Managers update team profiles" on public.profiles;
create policy "Active team can read profiles" on public.profiles for select to authenticated
using (public.current_user_active());
create policy "Users update own display name" on public.profiles for update to authenticated
using (id=(select auth.uid())) with check (
  id=(select auth.uid()) and role=public.current_user_role() and is_active=public.current_user_active()
);
create policy "Managers update team profiles" on public.profiles for update to authenticated
using (public.is_manager()) with check (public.is_manager());
