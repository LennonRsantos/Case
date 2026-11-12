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

-- 8. Owner email lives only in the database, never in git. `private` is not
-- exposed by the Data API. Seeded from whoever is already owner, so no
-- literal email is committed anywhere.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.owner_emails (email text primary key);

insert into private.owner_emails
  select lower(email) from public.profiles where role = 'owner'
  on conflict do nothing;

create or replace function public.is_admin_email(email text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from private.owner_emails o where o.email = lower(is_admin_email.email));
$$;

-- Was callable via RPC: anyone could test guesses to find the owner's email.
revoke execute on function public.is_admin_email(text) from anon, authenticated;

-- 9. Suspended accounts can't write anything, effective immediately (the
-- auth ban from block 1 only stops new sessions; a live token lasts up to
-- 1h). Fires inside SECURITY DEFINER RPCs too. DELETE stays allowed so a
-- suspended user can still remove their own content or delete the account.
create or replace function public.block_suspended_writes()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if auth.uid() is not null
     and exists (select 1 from public.profiles where id = auth.uid() and status = 'suspended') then
    raise exception 'account suspended';
  end if;
  return new;
end;
$$;

create trigger catalog_items_block_suspended before insert or update on public.catalog_items
  for each row execute function public.block_suspended_writes();
-- Only content columns: like_count/comment_count updates come from other
-- users' likes and from comment deletes, which must keep working.
create trigger posts_block_suspended before insert or update of rating, review, visibility, mentions, mentions_all on public.posts
  for each row execute function public.block_suspended_writes();
create trigger likes_block_suspended before insert or update on public.likes
  for each row execute function public.block_suspended_writes();
create trigger comments_block_suspended before insert or update on public.comments
  for each row execute function public.block_suspended_writes();
create trigger friendships_block_suspended before insert or update on public.friendships
  for each row execute function public.block_suspended_writes();
create trigger follows_block_suspended before insert or update on public.follows
  for each row execute function public.block_suspended_writes();
create trigger feedback_block_suspended before insert or update on public.feedback_submissions
  for each row execute function public.block_suspended_writes();

-- 10. profiles.email always mirrors the real login email: users can't fake
-- it (the admin panel shows it), and it now follows email changes.
create or replace function public.enforce_profile_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.email is distinct from (select u.email from auth.users u where u.id = new.id) then
    raise exception 'profile email must match the account email';
  end if;
  return new;
end;
$$;

create trigger profiles_enforce_email
  before update of email on public.profiles
  for each row execute function public.enforce_profile_email();

create or replace function public.sync_profile_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.profiles set email = new.email where id = new.id;
  return new;
end;
$$;

create trigger on_auth_user_email_changed
  after update of email on auth.users
  for each row execute function public.sync_profile_email();
