
drop policy if exists "Managers read invitations" on public.invitations;
drop policy if exists "Team read publications" on public.schedule_publications;
create policy "Team read publications" on public.schedule_publications for select to authenticated
using (public.current_user_active());

create index if not exists shift_requests_employee_idx on public.shift_requests(employee_id);
create index if not exists shift_requests_reviewer_idx on public.shift_requests(reviewed_by);
create index if not exists shift_requests_shift_idx on public.shift_requests(shift_id);
create index if not exists shift_requests_target_employee_idx on public.shift_requests(target_employee_id);
create index if not exists shift_requests_target_shift_idx on public.shift_requests(target_shift_id);
create index if not exists shifts_created_by_idx on public.shifts(created_by);
create index if not exists shifts_updated_by_idx on public.shifts(updated_by);
create index if not exists invitations_invited_by_idx on public.invitations(invited_by);
create index if not exists audit_log_actor_idx on public.audit_log(actor_id);
create index if not exists schedule_publications_publisher_idx on public.schedule_publications(published_by);
