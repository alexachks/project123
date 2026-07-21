-- =============================================================================
-- Базовая схема: профили пользователей и вендоры.
--
-- Роль пользователя НЕ хранится флагом. Человек является вендором тогда,
-- когда у него есть запись в public.vendors. Это позволяет одному
-- пользователю быть и клиентом, и вендором одновременно.
-- =============================================================================


-- =============================================================================
-- PROFILES — публичные данные пользователя (1:1 с auth.users)
-- =============================================================================

create table public.profiles (
  id          uuid        primary key references auth.users (id) on delete cascade,
  full_name   text,
  avatar_url  text,
  is_admin    boolean     not null default false,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

comment on table public.profiles is
  'Профиль пользователя. Создаётся автоматически при регистрации.';
comment on column public.profiles.is_admin is
  'Права модерации. Меняется только напрямую в БД, не через API.';


-- =============================================================================
-- VENDORS — бизнес-профиль. Наличие записи = пользователь является вендором.
-- =============================================================================

create type public.vendor_status as enum (
  'draft',      -- вендор заполняет профиль, никому не виден
  'pending',    -- отправлен на модерацию
  'published',  -- виден в публичном каталоге
  'suspended'   -- скрыт администратором
);

create table public.vendors (
  id             uuid                 primary key default gen_random_uuid(),
  owner_id       uuid                 not null references auth.users (id) on delete cascade,
  business_name  text                 not null check (length(trim(business_name)) between 2 and 120),
  slug           text                 not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  description    text                 check (length(description) <= 5000),
  city           text                 not null default 'San Diego',
  status         public.vendor_status not null default 'draft',
  created_at     timestamptz          not null default now(),
  updated_at     timestamptz          not null default now()
);

comment on table public.vendors is
  'Бизнес-профиль вендора. Один пользователь может владеть несколькими.';
comment on column public.vendors.slug is
  'Человекочитаемый URL: /vendors/sunny-coffee-cart. Только [a-z0-9-].';
comment on column public.vendors.city is
  'Заложено под расширение за пределы Сан-Диего.';

create index vendors_owner_id_idx on public.vendors (owner_id);
create index vendors_published_idx on public.vendors (city, created_at desc)
  where status = 'published';


-- =============================================================================
-- Триггеры
-- =============================================================================

-- updated_at обновляется автоматически при любом UPDATE
create function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

create trigger vendors_set_updated_at
  before update on public.vendors
  for each row execute function public.set_updated_at();


-- Профиль создаётся автоматически при регистрации.
-- Без этого после signup получим залогиненного пользователя без профиля.
-- SECURITY DEFINER: триггер срабатывает от имени auth-сервиса, которому
-- RLS-политики public.profiles недоступны.
create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, avatar_url)
  values (
    new.id,
    nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''),
    nullif(trim(new.raw_user_meta_data ->> 'avatar_url'), '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- =============================================================================
-- Хелперы для RLS
-- =============================================================================

-- Проверка прав администратора.
-- SECURITY DEFINER обязателен: иначе чтение profiles внутри политики
-- на profiles вызовет бесконечную рекурсию.
create function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (select p.is_admin from public.profiles p where p.id = (select auth.uid())),
    false
  );
$$;


-- =============================================================================
-- RLS: PROFILES
-- =============================================================================

alter table public.profiles enable row level security;

create policy "profiles_select_own"
  on public.profiles for select
  to authenticated
  using ((select auth.uid()) = id);

create policy "profiles_select_admin"
  on public.profiles for select
  to authenticated
  using (public.is_admin());

create policy "profiles_update_own"
  on public.profiles for update
  to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

-- INSERT политики нет: профиль создаёт только триггер.
-- DELETE политики нет: профиль удаляется каскадом вместе с auth.users.


-- Публичные поля профиля отдаются через view, а не через таблицу.
-- Так имя и аватар владельца вендора видны всем, а is_admin — нет.
create view public.public_profiles
with (security_invoker = true)
as
  select p.id, p.full_name, p.avatar_url
  from public.profiles p
  where exists (
    select 1 from public.vendors v
    where v.owner_id = p.id and v.status = 'published'
  );

comment on view public.public_profiles is
  'Безопасная проекция profiles: только владельцы опубликованных вендоров.';

grant select on public.public_profiles to anon, authenticated;

-- View с security_invoker читает profiles от имени вызывающего,
-- поэтому нужна политика, разрешающая чтение публичных владельцев.
create policy "profiles_select_public_vendor_owners"
  on public.profiles for select
  to anon, authenticated
  using (
    exists (
      select 1 from public.vendors v
      where v.owner_id = profiles.id and v.status = 'published'
    )
  );


-- =============================================================================
-- RLS: VENDORS
-- =============================================================================

alter table public.vendors enable row level security;

create policy "vendors_select_published"
  on public.vendors for select
  to anon, authenticated
  using (status = 'published');

create policy "vendors_select_own"
  on public.vendors for select
  to authenticated
  using ((select auth.uid()) = owner_id);

create policy "vendors_select_admin"
  on public.vendors for select
  to authenticated
  using (public.is_admin());

-- Вендор создаёт профиль только в статусе draft.
-- Опубликовать себя сам он не может — это делает модерация.
create policy "vendors_insert_own"
  on public.vendors for insert
  to authenticated
  with check ((select auth.uid()) = owner_id and status = 'draft');

create policy "vendors_update_own"
  on public.vendors for update
  to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);

create policy "vendors_update_admin"
  on public.vendors for update
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "vendors_delete_own"
  on public.vendors for delete
  to authenticated
  using ((select auth.uid()) = owner_id);


-- Владелец не может сам менять свой статус — иначе публикация в обход
-- модерации. Триггер разрешает только draft -> pending; остальные
-- переходы доступны администратору.
create function public.guard_vendor_status()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status is distinct from old.status
     and not public.is_admin()
     and not (old.status = 'draft' and new.status = 'pending')
  then
    raise exception 'Изменение статуса вендора доступно только администратору'
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

create trigger vendors_guard_status
  before update on public.vendors
  for each row execute function public.guard_vendor_status();
