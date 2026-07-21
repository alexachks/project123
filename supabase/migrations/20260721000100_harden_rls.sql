-- =============================================================================
-- Закрытие дыр, найденных при тестировании RLS.
--
-- 1. Пользователь мог выставить себе profiles.is_admin = true.
-- 2. Как следствие — сам себя опубликовать в обход модерации.
-- 3. Владелец мог сменить vendors.owner_id, передав бизнес другому аккаунту.
--
-- RLS в Postgres работает на уровне СТРОК, а не колонок: политика UPDATE
-- не умеет запрещать изменение отдельного поля. Поэтому неизменяемость
-- привилегированных колонок обеспечивается триггерами.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- 1. is_admin может менять только суперюзер / service_role напрямую в БД
-- -----------------------------------------------------------------------------

-- Запрос считается клиентским, если пришёл через PostgREST с JWT
-- (роли anon / authenticated). Прямое подключение к БД и service_role
-- под это условие не попадают.
create function public.is_api_request()
returns boolean
language sql
stable
as $$
  select current_user in ('anon', 'authenticated');
$$;

comment on function public.is_api_request is
  'true для запросов из браузера через PostgREST. Прямой доступ к БД и '
  'service_role возвращают false.';


create function public.guard_profile_privileges()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if not public.is_api_request() then
    return new;
  end if;

  if new.is_admin is distinct from old.is_admin then
    raise exception 'Изменение прав администратора через API запрещено'
      using errcode = 'insufficient_privilege';
  end if;

  -- id профиля привязан к auth.users, подмена недопустима
  if new.id is distinct from old.id then
    raise exception 'Изменение id профиля запрещено'
      using errcode = 'insufficient_privilege';
  end if;

  return new;
end;
$$;

comment on function public.guard_profile_privileges is
  'Блокирует эскалацию привилегий: is_admin выдаётся только напрямую в БД.';

create trigger profiles_guard_privileges
  before update on public.profiles
  for each row execute function public.guard_profile_privileges();


-- -----------------------------------------------------------------------------
-- 2. owner_id вендора неизменяем
-- -----------------------------------------------------------------------------

create function public.guard_vendor_owner()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.owner_id is distinct from old.owner_id then
    raise exception 'Смена владельца вендора запрещена'
      using errcode = 'insufficient_privilege';
  end if;
  return new;
end;
$$;

comment on function public.guard_vendor_owner is
  'WITH CHECK в RLS сверяется с новым значением, поэтому смену владельца '
  'политикой не поймать — нужен триггер.';

create trigger vendors_guard_owner
  before update on public.vendors
  for each row execute function public.guard_vendor_owner();


-- -----------------------------------------------------------------------------
-- 3. Явный отзыв прав на запись в is_admin у клиентских ролей.
--    Второй рубеж защиты помимо триггера.
-- -----------------------------------------------------------------------------

revoke update on public.profiles from anon, authenticated;

grant update (full_name, avatar_url) on public.profiles to authenticated;
