# 📦 Sber API SDK (Node.js)

Лёгкий и безопасный SDK для интеграции с SberAPI Сбербанка.: авторизация, H2H, моментальные платежи, зарплатные проекты и другие операции.
Содержит 3 модуля:
- Модуль авторизации (Базовый модуль включающий методы: Получения, обновления и отзыв токена. Смену клиентского секркта и получении информации о пользователе)
- Модуль прямой интеграции "h2h"
- Модуль моментальных платежей 

---

## Установка

Сборка sdk из исходного кода:

```bash
npm pack
```

Установка в свой проект `.tgz`-архива.

```bash
npm install ./sber-business-api-1.0.0.thz
```

---

# Настройка клиента
Для настройки клиента необходимо импортировать класс клиента 

```javascript
import ApiClient from './ApiClient.js';
```

и его сконфигурировать:
```javascript
const client = new ApiClient({
    conntectionTimeout: 60000,
    readTimeout: 60000,
    host: 'https://iftfintech.testsbi.sberbank.ru:9443',
    p12Path: '/SBBAPI_1958729756739688672_173a5fe4-68f5-4014-91c7-1730e19e3324.p12',
    caPath: '/russiantrustedca2024.pem',
    p12Password: 'certpass',
    enableLogs: true,
    maxRetries: 3,           // опционально: по умолчанию 3
    retryDelay: 1000,        // опционально: по умолчанию 1 сек
});
```

**Для метода проверки подписи ```javascript verifier.verifyJwt(result.id_token) ``` используется Java 1.8 +**

Примеры использования sdk в папке test

# Методы
Модуль Авторизации

[Получение кода авторизации, Обновление токена](https://developers.sber.ru/docs/ru/sber-api/specifications/oauth-token-post)
[Отзыв токена доступа](https://developers.sber.ru/docs/ru/sber-api/specifications/oauth-revoke-post)
[Получение информации о пользователе (user-info)](https://developers.sber.ru/docs/ru/sber-api/specifications/oauth-user-info-get)

Модуль прямой интеграции

[Запрос справочников](https://developers.sber.ru/docs/ru/sber-api/specifications/dicts/dicts-overview)
[Получение информации о клиенте](https://developers.sber.ru/docs/ru/sber-api/specifications/client-info/get-client-info)
[Получение криптоинформации](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/crypto-info-get)
[Получение криптоинформации](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/crypto-info-get)
[Получение криптоинформации для ЕИО](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/crypto-info-eio-get)
[Получение криптоинформации для ЕИО](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/crypto-info-eio-get)
[Создание запроса на новый сертификат](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/create-cert-request-post)
[Создание запроса на новый сертификат от ЕИО](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/create-cert-request-eio-post)
[Активация сертификата](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/activate-post)
[Активация сертификата для ЕИО](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/activate-eio-post)
[Получение печатной формы запроса на новый сертификат](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/print-get)
[Получение статуса запроса на новый сертификат](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/status-get)
[Получение статуса запроса на новый сертификат для ЕИО](https://developers.sber.ru/docs/ru/sber-api/specifications/crypto/status-eio-get)
[Создание рублевого платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/create-payment)
[Получение платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/get-payment)
[Получение статуса рублевого платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/get-payment-state)
[Получение статуса рублевого платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/get-payment-state)
[Запрос сводной информации по выписке](https://developers.sber.ru/docs/ru/sber-api/specifications/statement/summary)
[Получение операции по выписке](https://developers.sber.ru/docs/ru/sber-api/specifications/statement/transactions-id)
[Получение выписки по счету](https://developers.sber.ru/docs/ru/sber-api/specifications/statement/transactions)
[Создание зарплатной ведомости](https://developers.sber.ru/docs/ru/sber-api/specifications/payrolls/create)
[Получение зарплатной ведомости](https://developers.sber.ru/docs/ru/sber-api/specifications/payrolls/get-document)
[Получение статуса зарплатной ведомости](https://developers.sber.ru/docs/ru/sber-api/specifications/payrolls/get-state)

Модуль моментальных платежей

[Создание черновика платежного поручения по фиксированным реквизитам](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/create-payment-from-invoice)
[Создание черновика платежного поручения в бюджет](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/create-payment-from-invoice-budget)
[Создание черновика платежного поручения по свободным реквизитам](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/create-payment-from-invoice-any)
[Получение статуса рублевого платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/get-payment-state)
[Получение платежного поручения](https://developers.sber.ru/docs/ru/sber-api/specifications/payments/get-payment)


