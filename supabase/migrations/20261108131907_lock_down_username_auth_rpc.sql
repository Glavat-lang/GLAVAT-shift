revoke all on function public.create_team_invitation(text,text) from public, anon;
grant execute on function public.create_team_invitation(text,text) to authenticated;
revoke all on function public.auth_email_for_username(text) from public, anon, authenticated;
grant execute on function public.auth_email_for_username(text) to service_role;