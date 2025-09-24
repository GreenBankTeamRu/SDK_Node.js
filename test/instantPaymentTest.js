import fs from 'fs';
import path from 'path';

import ApiClient from '../lib/authorization/client.js';
import InstantPayment from '../lib/instantpayment/instantpaymentClient.js'
import SignatureVerificationService from '../lib/authorization/signatureVerificationService.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Путь к файлу для сохранения токена
const TOKEN_FILE_PATH = path.resolve(__dirname, "accessToken.json");
const _CODE = 'Eaac7A351E368C98A391E2Becda474E9fF95dC'
const _CLIENT_ID = '1958729756739688672'
const _REDIRECT_URI = 'http://ya.ru'
const _CLIENT_SECRET = 'LKHt5QGXihT5ltcu0pvNZERMRhOxcTLA'

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

const instantPaymentApi = new InstantPayment(client)

async function main() {
    // await getAccessToken();
    // await getPaymentInvoice();
    // await getPaymentInvoiceBudget();
    // await getPaymentInvoiceAnyBudget();
    // await getPaymentState();
    await getPayment();
    // await buildPaymentUrl();
}

async function getAccessToken() {
    try {
        const result = await client.getAccessToken({
            code: _CODE,
            client_id: _CLIENT_ID,
            redirect_uri: _REDIRECT_URI,
            client_secret: _CLIENT_SECRET,
        });

        console.log('Access Token received:', result.access_token);

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

function getPaymentInvoice() {
    try {
        const accessToken = loadAccessToken();

        const result = instantPaymentApi.getPaymentInvoice(accessToken, {
            "amount": 20.0,
            "date": "1900-03-13",
            "deliveryKind": "электронно",
            "expirationDate": "2025-06-23",
            "externalId": "64a0f829-b472-484e-867a-75d3fc19e1ef",
            "operationCode": "01",
            "orderNumber": "126",
            "payeeAccount": "40702810006000001792",
            "paymentNumber": "1",
            "priority": "5",
            "purpose": "Оплата заказа №123. НДС 20%",
            "urgencyCode": "NORMAL",
            "vat": {
                "type": "INCLUDED",
                "amount": 20.0,
                "rate": "20"
            }
        });

        console.log('response result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}
function getPaymentInvoiceBudget() {
    try {
        const accessToken = loadAccessToken();

        const result = instantPaymentApi.getPaymentInvoiceBudget(accessToken, {
            "amount": 20.0,
            "date": "1900-03-13",
            "deliveryKind": "электронно",
            "expirationDate": "2025-06-23",
            "externalId": "0951f710-9eb9-44da-b757-f3f35956e732",
            "operationCode": "01",
            "orderNumber": "126",
            "payeeAccount": "40702810006000001792",
            "paymentNumber": "1",
            "priority": "5",
            "purpose": "Оплата заказа №123. НДС 20%",
            "urgencyCode": "NORMAL",
            "vat": {
                "type": "INCLUDED",
                "amount": 20.0,
                "rate": "20"
            },
            "departmentalInfo": {
                "uip": "UIP12345678901234567890",
                "drawerStatus101": "01",
                "kbk": "18210102010011000110",
                "oktmo": "12345678901",
                "reasonCode106": "12",
                "taxPeriod107": "ГД.00.2018",
                "docNumber108": "123",
                "paymentKind110": "12"
            },
            "payeeBankBic": "044525225",
            "payeeBankCorrAccount": "30101810400000000225",
            "payeeInn": "1234567890",
            "payeeKpp": "123456789",
            "payeeName": "Бюджетное учреждение"
        });

        console.log('response result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getPaymentInvoiceAnyBudget() {
    try {
        const accessToken = loadAccessToken();

        const result = instantPaymentApi.getPaymentInvoiceAny(accessToken, {
            "externalId": "2e9be564-ea83-4fd4-9668-9508f0c7f384",
            "amount": 20.0,
            "date": "2025-04-05",
            "purpose": "Оплата услуг",
            "payeeAccount": "40702810006000001792",
            "urgencyCode": "NORMAL",
            "paymentNumber": "123456",
            "deliveryKind": "электронно",
            "expirationDate": "2025-06-23",
            "operationCode": "01",
            "orderNumber": "ORDER-123",
            "priority": "5",
            "vat": {
                "amount": 20.0,
                "rate": "20",
                "type": "INCLUDED"
            },
            "creditContractNumber": "CREDIT-789",
            "isPaidByCredit": true,
            "payeeBankBic": "044525225",
            "payeeBankCorrAccount": "30101810400000000225",
            "payeeInn": "1234567890",
            "payeeKpp": "123456789",
            "payeeName": "Получатель ООО"
        });

        console.log('response result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function getPaymentState() {
    try {
        const accessToken = loadAccessToken();

        const result = instantPaymentApi.getPaymentState(accessToken, "2e9be564-ea83-4fd4-9668-9508f0c7f384");

        console.log('response result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}
function getPayment() {
    try {
        const accessToken = loadAccessToken();

        const result = instantPaymentApi.getPayment(accessToken);

        console.log('response result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

function buildPaymentUrl() {
    try {
        const result = instantPaymentApi.buildPaymentUrl("2e9be564-ea83-4fd4-9668-9508f0c7f384", 'ya.ru', 'SMS', '', false);
        console.log('response result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

main();
