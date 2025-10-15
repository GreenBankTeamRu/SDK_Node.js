import fs from 'fs';
import path from 'path';

import ApiClient from '../lib/authorization/client.js';
import SignatureVerificationService from '../lib/authorization/signatureVerificationService.js';
import SecurityService from '../lib/authorization/securityService.js'
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Путь к файлу для сохранения токена
const TOKEN_FILE_PATH = path.resolve(__dirname, "accessToken.json");
const _CODE = 'Место для GrandCode'
const _CLIENT_ID = 'Ваш clientId'
const _REDIRECT_URI = 'Uri указанный для редиректа'
const _CLIENT_SECRET = 'ваш clientSecret'

const verifier = new SignatureVerificationService('Путь до сертификата .cer');

const client = new ApiClient({
    conntectionTimeout: 60000,
    readTimeout: 60000,
    host: 'https://iftfintech.testsbi.sberbank.ru:9443',
    p12Path: 'Путь до сертификата .p12',
    caPath: 'Путь до сертификата (.pem)',
    p12Password: 'Пароль от p12',
    enableLogs: true,
    maxRetries: 3,           // опционально: по умолчанию 3
    retryDelay: 1000,        // опционально: по умолчанию 1 сек
});

async function main() {
    // await getAccessToken();
    // await getRefreshToken();
    // await getRevokeToken();
    // await getChangeClientSecret();
    // await getUserInfo();
    // await pCSETest();
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

async function getAccessToken() {
    try {
        const result = await client.getAccessToken({
            code: _CODE,
            client_id: _CLIENT_ID,
            redirect_uri: _REDIRECT_URI,
            client_secret: _CLIENT_SECRET,
            // code_verifier: "12345678"
        });

        console.log('Access Token received:', result.access_token);

        // Сохраняем токен в файл
        saveAccessToken(result.access_token);

        console.log('Проверка jwt:')
        // Сервис проверки JWT использует Java 1.8
        let verifyJwtResult = verifier.verifyJwt(result.id_token)
        console.log(JSON.stringify(verifyJwtResult))

    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getRefreshToken() {
    try {
        const result = await client.getRefreshToken({
            refresh_token: '25e32a77Fc1dEe64d8e25bf729e5c514dBA50E',
            client_id: _CLIENT_ID,
            redirect_uri: _REDIRECT_URI,
            client_secret: _CLIENT_SECRET,
        });

        console.log('Refresh Token result:', result.data);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getRevokeToken() {
    try {
        // Загружаем токен из файла
        const accessToken = loadAccessToken();

        const result = await client.getRevokeToken(accessToken,
            {
                client_id: _CLIENT_ID,
                client_secret: _CLIENT_SECRET,
                token_type_hint: 'refresh_token',
                token: accessToken
            });

        console.log('Revoke Token result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getChangeClientSecret() {
    try {
        const accessToken = loadAccessToken();

        const result = await client.getChangeClientSecret(accessToken,
            {
                client_id: _CLIENT_ID,
                client_secret: _CLIENT_SECRET
            });

        console.log('Change Client Secret result:', result);
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function getUserInfo() {
    try {
        const accessToken = loadAccessToken();

        const result = await client.getUserInfo(accessToken);

        console.log('Проверка jwt:')
        // Сервис проверки JWT использует Java 1.8
        let verifyJwtResult = verifier.verifyJwt(result.jwt);
        console.log(JSON.stringify(verifyJwtResult))
        return verifyJwtResult;
    } catch (error) {
        console.error('Error:', error.message);
    }
}


async function pCSETest() {
    const securityService = new SecurityService();

    const verifier = securityService.generatePKCECodeVerifier();
    console.log('Code Verifier:', verifier);

    const challenge = securityService.generatePKCECodeChallenge(verifier);
    console.log('Code Challenge:', challenge);
}

main();
