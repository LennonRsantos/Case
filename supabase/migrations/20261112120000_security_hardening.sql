-- Security hardening from the 2026-11-12 audit. Each block closes one hole
-- that was only enforced in the browser (which anyone can bypass with the
-- public key) or that leaked through Supabase's default grants.

-- 1. Account status: only the owner may suspend/reactivate, and suspension
-- is enforced by Supabase Auth itself (banned users can't sign in or refresh
-- their session), not just by the React app.
-- auth.uid() is null only for trusted server contexts (service role, SQL
-- editor) — RLS already stops anon from updating profiles at all.
create or replace function public.enforce_status_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status is distinct from old.status then
    if auth.uid() is not null and not public.is_admin() then
      raise exception 'only the owner can change account status';
    end if;
    update auth.users
      set banned_until = case when new.status = 'suspended' then 'infinity'::timestamptz else null end
      where id = new.id;
  end if;
  return new;
end;
$$;

create trigger profiles_enforce_status_change
  before update of status on public.profiles
  for each row execute function public.enforce_status_change();

-- 2. Internal helpers: Supabase grants EXECUTE to anon/authenticated by name,
-- so the earlier "revoke ... from public" left them callable via RPC (anyone
-- could forge mention notifications as any user). Revoke from the real roles.
revoke execute on function public._notify_mentions(uuid, uuid, text, text, text, text, jsonb, boolean, uuid[], uuid, text) from anon, authenticated;
revoke execute on function public.can_uid_read_post(uuid, uuid) from anon, authenticated;

-- 3. can_read_post leaned on posts' RLS, but inside SECURITY DEFINER RPCs
-- (toggle_like, add_comment) the table owner bypasses RLS, so it always said
-- yes. Evaluate the same visibility rule explicitly for the calling user.
create or replace function public.can_read_post(target_post_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.can_uid_read_post(auth.uid(), target_post_id), false);
$$;

-- 4. signup_enabled is now enforced at the database: a signup while it's off
-- fails the whole auth.users insert (email/password and Google alike). The
-- owner email is exempt so the owner can never lock themselves out.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin_email(new.email)
     and not coalesce((select signup_enabled from public.app_settings limit 1), true) then
    raise exception 'signup is disabled';
  end if;

  insert into public.profiles (id, name, email, role, handle)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'name', split_part(new.email, '@', 1)),
    new.email,
    case when public.is_admin_email(new.email) then 'owner' else 'user' end,
    coalesce(new.raw_user_meta_data ->> 'handle', public.generate_handle(coalesce(new.raw_user_meta_data ->> 'name', 'Usuario')))
  );
  return new;
end;
$$;

-- 5. Posts are only created through publish_post(), which takes the author's
-- name/avatar from the server. A direct insert let anyone pick any name.
drop policy if exists "posts_insert_own" on public.posts;
revoke insert on public.posts from anon, authenticated;

-- 6. No reading the user directory without signing in.
revoke select on public.public_profiles, public.favorites_public, public.public_genre_prefs from anon;

drop policy if exists "follows_select_all" on public.follows;
create policy "follows_select_authenticated"
  on public.follows for select
  to authenticated
  using (true);
revoke select on public.follows from anon;

-- 7. image/* includes SVG, which can carry script. Allow raster formats only.
update storage.buckets
  set allowed_mime_types = array['image/png', 'image/jpeg', 'image/webp', 'image/gif']
  where id in ('avatars', 'covers');
