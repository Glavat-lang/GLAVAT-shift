
alter table public.shift_requests add column if not exists target_shift_id uuid references public.shifts(id) on delete set null;

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
      update public.shifts set employee_id=req.target_employee_id,updated_by=(select auth.uid()),updated_at=now() where id=original_shift.id;
      update public.shifts set employee_id=req.employee_id,updated_by=(select auth.uid()),updated_at=now() where id=target_shift.id;
    end if;
  end if;
  update public.shift_requests set status=p_decision,reviewer_comment=coalesce(p_comment,''),reviewed_by=(select auth.uid()),reviewed_at=now(),updated_at=now() where id=p_request_id;
end;
$$;
revoke all on function public.review_shift_request(uuid,text,text) from public,anon;
grant execute on function public.review_shift_request(uuid,text,text) to authenticated;
