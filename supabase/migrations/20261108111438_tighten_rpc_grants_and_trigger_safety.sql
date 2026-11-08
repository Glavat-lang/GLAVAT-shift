
revoke all on function public.audit_shift_changes() from public, anon, authenticated;
revoke all on function public.handle_new_user() from public, anon, authenticated;
revoke all on function public.notify_shift_change() from public, anon, authenticated;
revoke all on function public.notify_request_review() from public, anon, authenticated;
revoke all on function public.prevent_shift_overlap() from public, anon, authenticated;
revoke all on function public.current_user_active() from public, anon;
revoke all on function public.current_user_role() from public, anon;
revoke all on function public.is_manager() from public, anon;
revoke all on function public.is_owner() from public, anon;
revoke all on function public.create_team_invitation(text,text) from public, anon;
revoke all on function public.publish_schedule(date,text) from public, anon;
revoke all on function public.review_shift_request(uuid,text,text) from public, anon;
revoke all on function public.update_my_profile(text) from public, anon;
grant execute on function public.current_user_active() to authenticated;
grant execute on function public.current_user_role() to authenticated;
grant execute on function public.is_manager() to authenticated;
grant execute on function public.is_owner() to authenticated;
grant execute on function public.create_team_invitation(text,text) to authenticated;
grant execute on function public.publish_schedule(date,text) to authenticated;
grant execute on function public.review_shift_request(uuid,text,text) to authenticated;
grant execute on function public.update_my_profile(text) to authenticated;

create or replace function public.notify_shift_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare recipient uuid; msg text; ttl text;
begin
  if tg_op='INSERT' then
    ttl:='Новая смена';
    msg:='В расписании появилась смена на '||to_char(new.shift_date,'DD.MM.YYYY')||' с '||left(new.start_time::text,5)||' до '||left(new.end_time::text,5)||'.';
    recipient:=new.employee_id;
  elsif tg_op='UPDATE' then
    if row(new.shift_date,new.start_time,new.end_time,new.employee_id,new.status) is not distinct from row(old.shift_date,old.start_time,old.end_time,old.employee_id,old.status) then return new; end if;
    ttl:='Изменение смены';
    msg:='Изменена ваша смена на '||to_char(new.shift_date,'DD.MM.YYYY')||'.';
    recipient:=new.employee_id;
  else
    ttl:='Смена удалена';
    msg:='Ваша смена на '||to_char(old.shift_date,'DD.MM.YYYY')||' удалена.';
    recipient:=old.employee_id;
  end if;
  if recipient is not null then
    insert into public.notifications(user_id,title,body,kind,entity_type,entity_id)
    values(recipient,ttl,msg,'schedule','shift',case when tg_op='DELETE' then old.id else new.id end);
  end if;
  if tg_op='DELETE' then return old; else return new; end if;
end;
$$;
revoke all on function public.notify_shift_change() from public, anon, authenticated;

create or replace function public.prevent_shift_overlap()
returns trigger language plpgsql set search_path = ''
as $$
declare new_start timestamp; new_end timestamp;
begin
  if new.status='cancelled' then return new; end if;
  new_start:=new.shift_date+new.start_time;
  new_end:=new.shift_date+new.end_time;
  if new_end<=new_start then new_end:=new_end+interval '1 day'; end if;
  if exists(
    select 1 from public.shifts s
    where s.employee_id=new.employee_id and s.id is distinct from new.id and s.status<>'cancelled'
      and tstzrange((s.shift_date+s.start_time) at time zone 'UTC',
        (s.shift_date+s.end_time+case when s.end_time<=s.start_time then interval '1 day' else interval '0 day' end) at time zone 'UTC','[)')
      && tstzrange(new_start at time zone 'UTC',new_end at time zone 'UTC','[)')
  ) then raise exception 'У сотрудника уже есть пересекающаяся смена'; end if;
  return new;
end;
$$;
revoke all on function public.prevent_shift_overlap() from public, anon, authenticated;
