import fs from 'fs';
import path from 'path';

import ApiClient from '../lib/authorization/client.js';
import H2hClient from '../lib/h2h/h2hClient.js'
import SignatureVerificationService from '../lib/authorization/signatureVerificationService.js';
import {fileURLToPath} from 'url';
import {dirname} from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Путь к файлу для сохранения токена
const TOKEN_FILE_PATH = path.resolve(__dirname, "accessToken.json");
const _CODE = 'EFB0dAca0FeD5639750c390d7eeE1a1FCa89F2'
const _CLIENT_ID = '1958729756739688672'
const _REDIRECT_URI = 'http://ya.ru'
const _CLIENT_SECRET = 'rwhHCAJ6tTAoelFMOIgecDKS9EXEdD6z'

// const verifier = new SignatureVerificationService('/Users/18701423/Downloads/00CA0721_тестовый корень Минцифры.cer');

const client = new ApiClient({
    conntectionTimeout: 60000,
    readTimeout: 60000,
    host: 'https://iftfintech.testsbi.sberbank.ru:9443',
    p12Path: '/Users/18701423/Downloads/SBBAPI_1958729756739688672_173a5fe4-68f5-4014-91c7-1730e19e3324.p12',
    caPath: '/Users/18701423/Documents/certs/минЦифры/russiantrustedca2024.pem',
    p12Password: 'Yjubherb123',
    enableLogs: true,
    maxRetries: 3,           // опционально: по умолчанию 3
    retryDelay: 1000,        // опционально: по умолчанию 1 сек
});

const h2hClient = new H2hClient(client)

async function main() {
    // await getAccessToken();
    // await getDictionary();
    // await getClientInfo();
    // await getCrypto();
    // await getCryptoEio();
    // await certificateRequest();
    // await certificateRequestEIO();
    // await activateCertEIO();
    // await activateCert();
    // await printCert();
    // await getCertState();
    // await getCertStateEIO();
    await createPayment();
    // await getPayment();
    // await getPaymentDocState();
    // await getStatementSummary();
    // await getStatementTransactionId();
    // await getStatementTransactions();
    // await createPayroll();
    // await getPayroll();
    // await getPayrollState();
}

async function getAccessToken() {
    try {
        const result = await client.getAccessToken({
            code: _CODE,
            client_id: _CLIENT_ID,
            redirect_uri: _REDIRECT_URI,
            client_secret: _CLIENT_SECRET,
        });

        console.log('Access Token received:', JSON.stringify(result.access_token, null, 2));

        // Сохраняем токен в файл
        saveAccessToken(result.access_token);

        console.log('Проверка jwt:')
        // Сервис проверки JWT использует Java 1.8
        // let verifyJwtResult = verifier.verifyJwt(result.id_token)
        // console.log(JSON.stringify(verifyJwtResult))

    } catch (error) {
        console.error('Error:', error.message);
    }
}

function saveAccessToken(accessToken) {
    const data = JSON.stringify({accessToken});
    fs.writeFileSync(TOKEN_FILE_PATH, data, {encoding: "utf8"});
}

function loadAccessToken() {
    if (!fs.existsSync(TOKEN_FILE_PATH)) {
        throw new Error("Access token file not found. Please call getAccessToken first.");
    }
    const data = fs.readFileSync(TOKEN_FILE_PATH, {encoding: "utf8"});
    return JSON.parse(data).accessToken;
}

function getDictionary() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getDictionary(accessToken, "BIC");

        console.info('Ответ:', JSON.stringify(result.content));
        console.info('Ответ:', JSON.stringify(result.content));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getClientInfo() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getClientInfo(accessToken);
        console.log('Response: ', result)
        console.log('Response: ', JSON.stringify(result));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getCrypto() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getCrypto(accessToken);

    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getCryptoEio() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getCryptoEio(accessToken);

        console.log('response result:', JSON.stringify(result, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function activateCertEIO() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.activateCertEIO(accessToken, "d3d86e6b-f3c4-4438-8268-6bae2e32a9b8");

        console.log('response result:', JSON.stringify(result, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function activateCert() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.activateCert(accessToken, "d3d86e6b-f3c4-4438-8268-6bae2e32a9b9");

        console.log('response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function certificateRequest() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.certificateRequest(accessToken, {
            email: "test@mail.ru",
            externalId: "530419c2-be00-4f12-a4eb-979661dd744e",
            number: "1",
            orgName: "ИНДИВИДУАЛЬНЫЙ ПРЕДПРИНИМАТЕЛЬ ОТЕКА",
            pkcs10: {
                bicryptId: "A00ESYFHs.СУД С С",
                cms: "-----BEGIN CERTIFICATE REQUEST-----\nMIICEjCCAb8CAQAwgeMxCzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy\n0LAxTzBNBgNVBAoMRtCY0J3QlNCY0JLQmNCU0KPQkNCb0KzQndCr0Jkg0J/QoNCV\n0JTQn9Cg0JjQndCY0JzQkNCi0JXQm9CsINCe0KLQldCa0JAxFjAUBgNVBAsMDUlU\nIERlcGFydG1lbnQxGTAXBgNVBAwMENCU0LjRgNC10LrRgtC+0YAxFTATBgNVBAMM\nDNCh0KPQlCDQoSDQoTEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBzYmVyYmFuay5y\ndTBoMCEGCCqFAwcBAQEBMBUGCSqFAwcBAgEBAQYIKoUDBwEBAgIDQwAEQOWZtNN9\nHN5C6teBpGepq3mlYEfLZW4qFX/K9tE6u3jtP6y51ub6dOsjXEAFP1ovZ0L1H9IO\nGrIYkpsninOHbI6gajBoBgkqhkiG9w0BCQ4xWzBZMCMGByqFAwN7AwEEGAwWQTAw\nRVNZRkhzLtCh0KPQlCDQoSDQoTAOBgNVHQ8BAf8EBAMCBPAwDAYDVR0TBAUwAwIB\nADAUBgcqhQMDewMEBAkGByqFAwN7BRgwCgYIKoUDBwEBAwIDQQA/jpv/GZWdlxhe\nWgz0WIOMBzzAcJk0lQ2voksqvGzsyRCAtB1nky1u+E6XtB3K0jHuu+PKY1UyEodZ\nGu0S8N4o\n-----END CERTIFICATE REQUEST-----\n"
            },
            userName: "СУД С С",
            userPosition: "Директор"
        });

        console.log('Dict response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function certificateRequestEIO() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.certificateRequestEIO(accessToken, {
            email: "test@mail.ru",
            login: "sdkoteka",
            externalId: "530419c2-be00-4f12-a4eb-979661dd744e",
            number: "1",
            orgName: "ИНДИВИДУАЛЬНЫЙ ПРЕДПРИНИМАТЕЛЬ ОТЕКА",
            pkcs10: {
                bicryptId: "A00ESYFHs.СУД С С",
                cms: "-----BEGIN CERTIFICATE REQUEST-----\nMIICEjCCAb8CAQAwgeMxCzAJBgNVBAYTAlJVMRUwEwYDVQQHDAzQnNC+0YHQutCy\n0LAxTzBNBgNVBAoMRtCY0J3QlNCY0JLQmNCU0KPQkNCb0KzQndCr0Jkg0J/QoNCV\n0JTQn9Cg0JjQndCY0JzQkNCi0JXQm9CsINCe0KLQldCa0JAxFjAUBgNVBAsMDUlU\nIERlcGFydG1lbnQxGTAXBgNVBAwMENCU0LjRgNC10LrRgtC+0YAxFTATBgNVBAMM\nDNCh0KPQlCDQoSDQoTEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBzYmVyYmFuay5y\ndTBoMCEGCCqFAwcBAQEBMBUGCSqFAwcBAgEBAQYIKoUDBwEBAgIDQwAEQOWZtNN9\nHN5C6teBpGepq3mlYEfLZW4qFX/K9tE6u3jtP6y51ub6dOsjXEAFP1ovZ0L1H9IO\nGrIYkpsninOHbI6gajBoBgkqhkiG9w0BCQ4xWzBZMCMGByqFAwN7AwEEGAwWQTAw\nRVNZRkhzLtCh0KPQlCDQoSDQoTAOBgNVHQ8BAf8EBAMCBPAwDAYDVR0TBAUwAwIB\nADAUBgcqhQMDewMEBAkGByqFAwN7BRgwCgYIKoUDBwEBAwIDQQA/jpv/GZWdlxhe\nWgz0WIOMBzzAcJk0lQ2voksqvGzsyRCAtB1nky1u+E6XtB3K0jHuu+PKY1UyEodZ\nGu0S8N4o\n-----END CERTIFICATE REQUEST-----\n"
            },
            userName: "СУД С С",
            userPosition: "Директор"
        });

        console.log('response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getCertState() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getCertState(accessToken, "7e6b5fa3-78df-4e15-b97e-59bffa60cece");

        console.log('response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}


function getCertStateEIO() {
    try {
        const accessToken = loadAccessToken();

        const result = h2hClient.getCertStateEIO(accessToken, "7e6b5fa3-78df-4e15-b97e-59bffa60cece");

        console.log('response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function printCert() {
    try {
        const accessToken = loadAccessToken();

        const result = await h2hClient.printCert(
            accessToken,
            "530419c2-be00-4f12-a4eb-979661dd774e"
        );

        await fs.promises.writeFile('certificate.pdf', Buffer.from(result, 'binary'));
        console.log('PDF успешно сохранён в: certificate.pdf');
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function createPayment() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.createPayment(
            accessToken,
            {
                "date": "2025-04-05",
                "amount": 150.10,
                "deliveryKind": "электронно",
                "departmentalInfo": {
                    "docNumber108": "123",
                    "oktmo": "132",
                    "reasonCode106": "01",
                    "uip": "0",
                    "taxPeriod107": "ГД.00.2018",
                    "drawerStatus101": "01",
                    "docDate109": "01.01.2001",
                    "kbk": "18210102010011000110"
                },
                "externalId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "urgencyCode": "NORMAL",
                "operationCode": "01",
                "payeeAccount": "40702810538710000788",
                "payeeBankBic": "044525225",
                "payeeBankCorrAccount": "30101810400000000225",
                "payeeInn": "4459195834",
                "payeeName": "Питончик",
                "payeeKpp": "583501001",
                "payerAccount": "40702810438178296467",
                "payerBankBic": "044528425",
                "payerBankCorrAccount": "30101810400000000225",
                "payerInn": "4459195834",
                "payerName": "Питончик",
                "priority": "5",
                "purpose": "В том числе НДС 20 % - 58.83 рублей.",
                "digestSignatures": [
                    {
                        "base64Encoded": "MIIMsAYJKoZIhvcNAQcCoIIMoTCCDJ0CAQExDjAMBggqhQMHAQECAgUAMAsGCSqGSIb3DQEHAaCCCZwwggSEMIIEMaADAgECAgp",
                        "certificateUuid": "e1746650-1234-4000-8000-000000000000"
                    }
                ],
                "vat": {
                    "type": "INCLUDED",
                    "rate": "7",
                    "amount": 9.81
                }
            }
        );

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getPayment() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getPayment(
            accessToken, "39cea241-fab2-415a-9fc0-19c9c4187d8b")

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getPaymentDocState() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getPaymentDocState(
            accessToken, "39cea241-fab2-415a-9fc0-19c9c4187d8b")

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getStatementSummary() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getStatementSummary(
            accessToken, "40702810738000017799", "2025-01-13")

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getStatementTransactionId() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getStatementTransactionId(
            accessToken, 1, "40702810738000017799", "2025-01-13")

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getStatementTransactions() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getStatementTransactions(
            accessToken, "40702810738000017799", "2025-01-13", 1, "curTransfer")

        console.log('Response data:', JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function createPayroll() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.createPayroll(
            accessToken, {
                "date": "2025-04-05",
                "account": "40702810738001373607",
                "admissionValue": "01",
                "amount": {
                    "amount": 12.0,
                    "currencyCode": "810",
                    "currencyName": "RUB"
                },
                "authPersonName": "ПЕСИК ПЕСИК ПЕСИКОВИЧ",
                "authPersonTelfax": "79998887744",
                "bic": "044525225",
                "contractDate": "2024-08-06",
                "contractNumber": "93136464",
                "digestSignatures": [
                    {
                        "base64Encoded": "MIIMsAYJKoZIhvcNAQcCoIIMoTCCDJ0CAQExDjAMBggqhQMHAQECAgUAMAsGCSqGSIb3DQEHAaCCCZwwggSEMIIEMaADAgE",
                        "certificateUuid": "e1746650-1234-4000-8000-000000000000"
                    }
                ],
                "employeeSalaries": [
                    {
                        "account": "42306810038170107028",
                        "amount": {
                            "amount": 12.0,
                            "currencyCode": "810",
                            "currencyName": "RUB"
                        },
                        "bic": "044525225",
                        "bankMessage": "0",
                        "firstName": "БУБЛИК",
                        "lastName": "БУБЛИК",
                        "middleName": "БУБЛИК",
                        "receiptResult": "0",
                        "receiptStatus": "0",
                        "result": "0",
                        "withheldAmount": 3
                    }
                ],
                "employeesNumber": 1,
                "externalId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "incomeTypeCode": "1",
                "loanAmount": {
                    "amount": 12.0,
                    "currencyCode": "643",
                    "currencyName": "RUB"
                },
                "loanDate": "2025-04-05",
                "loanNumber": "76",
                "month": "3",
                "number": "123",
                "orgName": "ООО Альфа",
                "orgTaxNumber": "9872124730",
                "payDocs": [
                    {
                        "amount": {
                            "amount": 12.0,
                            "currencyCode": "643",
                            "currencyName": "RUB"
                        },
                        "number": "123",
                        "payeeAccount": "40702810438178296467",
                        "docDate": "2025-04-05",
                        "payerAccount": "40702810438178296467",
                        "payeeBic": "044525225",
                        "payerBic": "044525225",
                        "purpose": "Причина"
                    }
                ],
                "year": "2025"
            })

        console.log('Response data:', JSON.stringify(JSON.stringify(data, null, 2), null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getPayroll() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getPayroll(
            accessToken, "39cea241-fab2-415a-9fc0-19c9c4187d8b")

        console.log('Response data:', JSON.stringify(JSON.stringify(data, null, 2), null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getPayrollState() {
    try {
        const accessToken = loadAccessToken();

        // Добавляем await здесь
        const result = await h2hClient.getPayrollState(
            accessToken, "39cea241-fab2-415a-9fc0-19c9c4187d8b")

        console.log('Response data:', JSON.stringify(JSON.stringify(data, null, 2), null, 2));
    } catch (error) {
        console.error('Error:', error.message);
    }
}

main();
