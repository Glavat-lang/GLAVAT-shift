
drop policy if exists "Managers manage publications" on public.schedule_publications;
create policy "Managers insert publications" on public.schedule_publications for insert to authenticated with check (public.is_manager());
create policy "Managers update publications" on public.schedule_publications for update to authenticated using (public.is_manager()) with check (public.is_manager());
create policy "Managers delete publications" on public.schedule_publications for delete to authenticated using (public.is_manager());
