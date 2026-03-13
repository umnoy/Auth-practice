# OAuth2 CSRF Login Attack CTF Lab
## Краткое описание уязвимости

**CSRF Login Attack** в OAuth2 появляется, когда приложение не связывает этап авторизации с конкретной сессией пользователя.
**Ключевая причина** это отсутствие генерации и проверки параметра state.
* Если state не проверяется, атакующий может получить authorization code для своего аккаунта и передать жертве ссылку на callback с этим code.
После перехода жертвы приложение завершит вход и создаст сессию жертвы в аккаунте атакующего.
Последствие атаки это подмена контекста входа, соответственно жертва работает в чужом аккаунте и может сама отправить туда приватные данные.
## Способы защиты

##### 1. Генерировать и проверять state
```python
state = secrets.token_urlsafe(32)
session['oauth_state'] = state
return redirect(f"{PROVIDER}/authorize?...&state={state}")
#генерация уникального state параметра 

#и дальнейшая его проверка в callback:
returned_state = request.args.get("state")
if not returned_state or returned_state != session.pop('oauth_state', None):
    abort(400, "Invalid state parameter — possible CSRF attack")
```
##### 2. Удалять использованный state сразу после проверки.
##### 3. Использовать PKCE для дополнительной защиты обмена code на token.
##### 4. Ограничивать redirect_uri заранее известными значениями.

## Запуск приложения
Требования:
- Docker
- Docker Compose
Команды:
```bash
docker compose up --build
```

Сервисы после запуска:
- SecureVault: http://localhost:5000
- OAuth Provider: http://localhost:5001
- Victim Bot: http://localhost:5002

Флаг задается в файле docker-compose.yml через переменную FLAG.
## Уязвимость в реализованном приложении

В приложении SecureVault уязвимость находится в маршрутах login и callback файла app/app.py.

**В login:**
- Приложение не генерирует state.
- Приложение не добавляет state в запрос authorize.
**В callback:**
- Приложение принимает code без проверки state.
- Приложение сразу обменивает code на token и создает сессию.
Из за этого любой code, полученный атакующим, может быть использован для входа жертвы в аккаунт атакующего.
## POC эксплоит для получения флага

##### 1. Способ через скрипт:
```bash
python exploit.py
```
Что делает скрипт:
1. Запускает OAuth flow от имени пользователя ctf_user.
2. Получает authorization coder.
3. Формирует ссылку на callback с этим code.
4. Отправляет боту.
5. Проверяет, что сессия жертвы стала сессией игрока.
##### 2. Вручную: 
1. Открыть http://localhost:5000 и открыть страницу авторизации на http://localhost:5001 путем нажатия на кнопку "авторизоваться"
2. Ввести логин и пароль от ctf_user
3. Через Burp Suite или альтернативными методами перехватить ответ от сервера и скопировать оттуда ссылку из поля Location:
4. Отправить ссылку через форму бота.
5. Бот перейдет по ссылке и запишет флаг в заметки аккаунта operator.
6. Открыть http://localhost:5000 и войти как ctf_user.
7. Получить флаг на странице dashboard.
## Дополнительные важные сведения

* Креды от пользователей находятся в файле /app/oauth_provider.py в словаре USERS:

```python
USERS = {
    "ctf_player": {
        "login": "ctf_player",
        "name": "ctf player",
        "id": 1337,
        "password_hash": generate_password_hash("123456"),
    },
    "victim": {
        "login": "victim",
        "name": "Innocent User",
        "id": 9001,
        "password_hash": generate_password_hash("J<jw$n$ruZXd@AA46ROqY#uD}f~~AvX<8/b@E2d0"),
    },
}
```

* От SSRF добавлены следующие меры защиты (все в bot.py):
1. Строгая валидация входного URL:
    1. Только http, хост *localhost/127.0.0.1*, порт 5000, путь */callback*, остальное мимо
    2. Обязательный непустой query-параметр code
    3. Запрет userinfo в URL
    4. Запрет fragment `#...`
2. Убрана regex-подмена URL 
3. Безопасная навигация по редиректам:
    1. Редиректы обрабатываются вручную
    2. Разрешены только редиректы внутри внутреннего webapp-хоста
    3. Внешние редиректы блокируются
    4. Есть лимит на количество редиректов

* В docker-compose SECRET_KEY для сессии flask, чтоб потом с демонстрационного на нормальный поменять