
create or replace function public.create_team_invitation(p_email text,p_role text default 'employee')
returns text language plpgsql security definer set search_path = ''
as $$
declare raw_token text:=encode(extensions.gen_random_bytes(32),'hex');
begin
  if not public.is_manager() then raise exception 'Недостаточно прав'; end if;
  if p_role not in ('admin','employee') then raise exception 'Недопустимая роль'; end if;
  if p_role='admin' and not public.is_owner() then raise exception 'Только владелец может приглашать администраторов'; end if;
  insert into public.invitations(email,role,token_hash,invited_by)
  values(lower(trim(p_email)),p_role,encode(extensions.digest(raw_token,'sha256'),'hex'),(select auth.uid()));
  return raw_token;
end;
$$;
revoke all on function public.create_team_invitation(text,text) from public,anon;
grant execute on function public.create_team_invitation(text,text) to authenticated;
