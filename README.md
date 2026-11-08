# GLAVAT SHIFT

Система расписания смен караоке «Баритон». React + Vite + Supabase Auth/PostgreSQL.

## Запуск локально

```bash
npm install
cp .env.example .env
npm run dev
```

В `.env` задаются `VITE_SUPABASE_URL` и `VITE_SUPABASE_ANON_KEY`. Используется только публичный publishable/anon ключ; service-role ключи в браузер не помещаются.

## Backend

Supabase project: `yumtvxckvwkpxvpferdq` (eu-west-1). Схема базы уже применена в отдельном проекте GLAVAT SHIFT. RLS включён на прикладных таблицах; роли owner/admin/employee. Приглашения и публикация графика выполняются серверными RPC.

## Deployment

GitHub Actions workflow собирает Vite и публикует каталог `dist` в GitHub Pages при push в `main`. В репозитории нужно один раз включить Pages: Settings → Pages → Build and deployment → Source: GitHub Actions.

## Текущие ограничения

Интерфейс и подключение Supabase являются начальной рабочей версией. Перед ежедневным использованием обязательны проверка первого входа владельца, приглашения сотрудников, прав RLS, конфликтов смен и полного цикла заявок на реальных тестовых аккаунтах. Email/push-уведомления и расширенные отчёты не заявляются как реализованные.