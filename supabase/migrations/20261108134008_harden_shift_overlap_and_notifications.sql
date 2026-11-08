create or replace function public.prevent_shift_overlap()
returns trigger
language plpgsql
set search_path = ''
as $function$
declare new_start timestamp; new_end timestamp;
begin
  if new.status = 'cancelled' or current_setting('app.skip_shift_overlap', true) = 'on' then return new; end if;
  perform pg_advisory_xact_lock(741234, hashtext(new.employee_id::text));
  new_start := new.shift_date + new.start_time;
  new_end := new.shift_date + new.end_time;
  if new_end <= new_start then new_end := new_end + interval '1 day'; end if;
  if exists (
    select 1 from public.shifts s
    where s.employee_id = new.employee_id and s.id is distinct from new.id and s.status <> 'cancelled'
      and tstzrange((s.shift_date+s.start_time) at time zone 'UTC',
        (s.shift_date+s.end_time+case when s.end_time<=s.start_time then interval '1 day' else interval '0 day' end) at time zone 'UTC','[)')
        && tstzrange(new_start at time zone 'UTC',new_end at time zone 'UTC','[)')
  ) then raise exception 'У сотрудника уже есть пересекающаяся смена'; end if;
  return new;
end;
$function$;

create or replace function public.notify_shift_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
declare recipient uuid; msg text; ttl text;
begin
  if tg_op = 'INSERT' then
    ttl := 'Новая смена';
    msg := 'В расписании появилась смена на '||to_char(new.shift_date,'DD.MM.YYYY')||' с '||left(new.start_time::text,5)||' до '||left(new.end_time::text,5)||'.';
    recipient := new.employee_id;
  elsif tg_op = 'UPDATE' then
    if row(new.shift_date,new.start_time,new.end_time,new.employee_id,new.status)
       is not distinct from row(old.shift_date,old.start_time,old.end_time,old.employee_id,old.status) then return new; end if;
    if old.employee_id is distinct from new.employee_id and old.employee_id is not null then
      insert into public.notifications(user_id,title,body,kind,entity_type,entity_id)
      values(old.employee_id,'Смена передана другому сотруднику',
        'Смена на '||to_char(old.shift_date,'DD.MM.YYYY')||' больше не закреплена за вами.','schedule','shift',new.id);
    end if;
    recipient := new.employee_id;
    if new.status = 'cancelled' then
      ttl := 'Смена отменена';
      msg := 'Ваша смена на '||to_char(new.shift_date,'DD.MM.YYYY')||' отменена.';
    elsif old.employee_id is distinct from new.employee_id then
      ttl := 'Новая смена назначена';
      msg := 'На вас назначена смена на '||to_char(new.shift_date,'DD.MM.YYYY')||' с '||left(new.start_time::text,5)||' до '||left(new.end_time::text,5)||'.';
    else
      ttl := 'Изменение смены';
      msg := 'Изменена ваша смена на '||to_char(new.shift_date,'DD.MM.YYYY')||': '||left(new.start_time::text,5)||'–'||left(new.end_time::text,5)||'.';
    end if;
  else
    ttl := 'Смена удалена';
    msg := 'Ваша смена на '||to_char(old.shift_date,'DD.MM.YYYY')||' удалена.';
    recipient := old.employee_id;
  end if;
  if recipient is not null then
    insert into public.notifications(user_id,title,body,kind,entity_type,entity_id)
    values(recipient,ttl,msg,'schedule','shift',case when tg_op='DELETE' then old.id else new.id end);
  end if;
  if tg_op='DELETE' then return old; end if;
  return new;
end;
$function$;