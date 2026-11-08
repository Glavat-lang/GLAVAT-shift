
create or replace function public.update_my_profile(p_full_name text)
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if not public.current_user_active() then raise exception 'Доступ отключён'; end if;
  update public.profiles set full_name=left(trim(p_full_name),100),updated_at=now()
  where id=(select auth.uid()) and length(trim(p_full_name)) between 1 and 100;
  if not found then raise exception 'Имя должно содержать от 1 до 100 символов'; end if;
end;
$$;
revoke all on function public.update_my_profile(text) from public;
grant execute on function public.update_my_profile(text) to authenticated;

drop policy if exists "Users update own display name" on public.profiles;
revoke update on public.profiles from authenticated;
grant update on public.profiles to authenticated;

do $$
begin
  alter publication supabase_realtime add table public.shifts;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.shift_requests;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.notifications;
exception when duplicate_object then null;
end $$;
