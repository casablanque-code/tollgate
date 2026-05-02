# Деплой на Vercel

## 1. Установи Vercel CLI
```bash
npm install -g vercel
```

## 2. Залогинься
```bash
vercel login
```

## 3. Деплой из папки проекта
```bash
cd porovnu
vercel
```
Vercel сам определит что это Vite проект.

## 4. Добавь переменные окружения
В Vercel Dashboard → твой проект → Settings → Environment Variables:
```
VITE_SUPABASE_URL = https://xxxx.supabase.co
VITE_SUPABASE_ANON_KEY = eyJ...
```

## 5. Редеплой с переменными
```bash
vercel --prod
```

## 6. Настрой домен в Supabase
В Supabase → Authentication → URL Configuration:
- Site URL: `https://твой-проект.vercel.app`
- Redirect URLs: `https://твой-проект.vercel.app/**`

## PWA — установка на телефон

### iPhone (Safari):
1. Открой сайт в Safari
2. Нажми кнопку "Поделиться" (квадрат со стрелкой)
3. Выбери "На экран «Домой»"
4. Нажми "Добавить"

### Android (Chrome):
1. Открой сайт в Chrome
2. Нажми меню (три точки)
3. Выбери "Добавить на главный экран"
4. Нажми "Установить"

После этого приложение открывается без браузера, как нативное.
