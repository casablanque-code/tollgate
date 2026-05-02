tags: [git]
GIT:
строчка - cd путь до папки с проектом
git init

Привязываем удалённый репозиторий
git remote add origin https://github.com/casablanque-code/repo_name.git

Добавляем файлы и коммитим
git add .
git commit -m "Текст коммита"

Пушим в ветку main (или любую другую):
git branch -M main
git push -u origin main

Дальше работаем по циклу
git add .
git commit -m "описание изменений"
git push

Шпаргалка “что делать” по симптомам
fetch first / non-fast-forward → у удалённой ветки есть новые коммиты.
Решение: git pull --rebase origin main → потом git push.

После правок на GitHub → всегда делай git pull --rebase перед новыми локальными пушами.

Нужно просто синхронизироваться (без локальных правок):
git fetch origin && git reset --hard origin/main.

Нужно перезаписать удалённую ветку своей локальной (крайний случай):
git push --force-with-lease origin main