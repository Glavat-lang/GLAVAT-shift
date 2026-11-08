
create or replace function public.prevent_shift_overlap()
returns trigger language plpgsql set search_path = ''
as $$
declare new_start timestamp; new_end timestamp;
begin
  if new.status='cancelled' or current_setting('app.skip_shift_overlap',true)='on' then return new; end if;
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
revoke all on function public.prevent_shift_overlap() from public,anon,authenticated;

create or replace function public.review_shift_request(p_request_id uuid,p_decision text,p_comment text default '')
returns void language plpgsql security definer set search_path = ''
as $$
declare req public.shift_requests%rowtype; target_shift public.shifts%rowtype; original_shift public.shifts%rowtype;
begin
  if not public.is_manager() then raise exception 'Недостаточно прав'; end if;
  if p_decision not in ('approved','rejected') then raise exception 'Недопустимое решение'; end if;
  select * into req from public.shift_requests where id=p_request_id for update;
  if not found or req.status<>'pending' then raise exception 'Заявка уже обработана или не найдена'; end if;
  if p_decision='approved' then
    if req.request_type='day_off' then
      update public.shifts set status='cancelled',updated_by=(select auth.uid()),updated_at=now()
      where employee_id=req.employee_id and shift_date=req.requested_date and status<>'cancelled';
    elsif req.request_type='time_change' then
      if req.shift_id is null or req.proposed_start is null or req.proposed_end is null then raise exception 'Для изменения времени укажите смену, начало и окончание'; end if;
      update public.shifts set start_time=req.proposed_start,end_time=req.proposed_end,updated_by=(select auth.uid()),updated_at=now()
      where id=req.shift_id and employee_id=req.employee_id;
      if not found then raise exception 'Смена не найдена'; end if;
    elsif req.request_type='replacement' then
      if req.shift_id is null or req.target_employee_id is null then raise exception 'Для замены выберите смену и сотрудника'; end if;
      update public.shifts set employee_id=req.target_employee_id,updated_by=(select auth.uid()),updated_at=now()
      where id=req.shift_id and employee_id=req.employee_id;
      if not found then raise exception 'Смена не найдена или уже назначена другому сотруднику'; end if;
    elsif req.request_type='swap' then
      if req.shift_id is null or req.target_shift_id is null or req.target_employee_id is null then raise exception 'Для обмена выберите обе смены и второго сотрудника'; end if;
      select * into original_shift from public.shifts where id=req.shift_id and employee_id=req.employee_id for update;
      select * into target_shift from public.shifts where id=req.target_shift_id and employee_id=req.target_employee_id for update;
      if original_shift.id is null or target_shift.id is null then raise exception 'Одна из смен не найдена или уже изменилась'; end if;
      perform set_config('app.skip_shift_overlap','on',true);
      update public.shifts set employee_id=req.target_employee_id,updated_by=(select auth.uid()),updated_at=now() where id=original_shift.id;
      update public.shifts set employee_id=req.employee_id,updated_by=(select auth.uid()),updated_at=now() where id=target_shift.id;
      perform set_config('app.skip_shift_overlap','off',true);
      if exists(
        select 1 from public.shifts a join public.shifts b on a.employee_id=b.employee_id and a.id<>b.id and b.status<>'cancelled'
        where a.id in (original_shift.id,target_shift.id) and a.status<>'cancelled'
          and tstzrange((a.shift_date+a.start_time) at time zone 'UTC',(a.shift_date+a.end_time+case when a.end_time<=a.start_time then interval '1 day' else interval '0 day' end) at time zone 'UTC','[)')
          && tstzrange((b.shift_date+b.start_time) at time zone 'UTC',(b.shift_date+b.end_time+case when b.end_time<=b.start_time then interval '1 day' else interval '0 day' end) at time zone 'UTC','[)')
      ) then raise exception 'После обмена возникнет пересечение смен'; end if;
    end if;
  end if;
  update public.shift_requests set status=p_decision,reviewer_comment=coalesce(p_comment,''),reviewed_by=(select auth.uid()),reviewed_at=now(),updated_at=now() where id=p_request_id;
end;
$$;
revoke all on function public.review_shift_request(uuid,text,text) from public,anon;
grant execute on function public.review_shift_request(uuid,text,text) to authenticated;

drop policy if exists "Managers update team profiles" on public.profiles;
create policy "Managers update team profiles" on public.profiles for update to authenticated
using (public.is_manager() and (role<>'owner' or public.is_owner()))
with check (public.is_manager() and (role=public.current_user_role() or public.is_owner()) and (role<>'owner' or public.is_owner()));
