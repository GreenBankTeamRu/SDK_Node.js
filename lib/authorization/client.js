import fs from 'fs';
import https from 'https';
import forge from 'node-forge';
import axios from 'axios';
import querystring from 'querystring';
import crypto from 'crypto';

import validators from './validators.js';
import { MaskingInterceptor } from './maskingInterceptor.js';

const { authorizationReqSchema, revokeTokenReqSchema, refreshTokenReqSchema, getRefreshClientSecretSchema, changeClientSecretSchema } = validators;

const DEFAULT_TIMEOUT = 60 * 1000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_DELAY = 1000;
const ALLOWED_CHARACTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';


class ApiClient {
    constructor(config) {
        this._validateConfig(config);
        this.host = config.host;
        this.config = {
            connectTimeout: config.connectTimeout || DEFAULT_TIMEOUT,
            readTimeout: config.readTimeout || DEFAULT_TIMEOUT,
            p12Path: config.p12Path,
            p12Password: config.p12Password,
            caPath: config.caPath,
            enableLogs: config.enableLogs || false,
            maxRetries: config.maxRetries !== undefined ? config.maxRetries : DEFAULT_MAX_RETRIES,
            retryDelay: config.retryDelay || DEFAULT_RETRY_DELAY,
        };

        this.httpClient = this.createHttpClient();
    }

    _validateConfig(config) {
        if (!config.host) throw new Error("Host is required");
        if (!config.p12Path) throw new Error("Path to p12 certificate is required");
    }

    createHttpClient() {
        const sslOptions = this._createSslOptions();
        const client = axios.create({
            baseURL: this.host,
            httpsAgent: new https.Agent(sslOptions),
            timeout: this.config.connectTimeout,
        });

        if (this.config.enableLogs) {
            client.interceptors.request.use(
                (config) => {
                    this._logRequest(config);
                    return config;
                },
                (error) => Promise.reject(error)
            );

            client.interceptors.response.use(
                (response) => {
                    this._logResponse(response);
                    return response;
                },
                (error) => Promise.reject(error)
            );
        }

        return client;
    }

    _logRequest(config) {
        if (MaskingInterceptor.shouldExcludeLogging(config.url, this.host)) return;

        const maskedUrl = MaskingInterceptor.maskUrl(config.url, config.params, this.host);
        console.log(`Outgoing Request: ${config.method?.toUpperCase()} ${maskedUrl}`);

        const maskedHeaders = MaskingInterceptor.maskHeaders(config.headers);
        console.log('Headers:', maskedHeaders);

        if (config.data) {
            const contentType = config.headers['Content-Type'] || config.headers['content-type'];
            const maskedBody = MaskingInterceptor.maskBody(config.data, contentType);
            console.log('Request Body:', maskedBody);
        }
    }

    _logResponse(response) {
        if (MaskingInterceptor.shouldExcludeLogging(response.config.url, this.host)) return;

        console.log(`Response: ${response.status}`);

        const maskedHeaders = MaskingInterceptor.maskHeaders(response.headers);
        console.log('Headers:', maskedHeaders);

        if (response.data) {
            const contentType = response.headers['content-type'];
            const maskedBody = MaskingInterceptor.maskBody(response.data, contentType);
            console.log('Response Body:', maskedBody);
        }
    }

    _sanitizeHeaders(headers) {
        if (!headers) return headers;
        const clean = { ...headers };
        if (clean.authorization) clean.authorization = '[REDACTED]';
        if (clean.Authorization) clean.Authorization = '[REDACTED]';
        return clean;
    }

    _createSslOptions() {
        const p12 = this._loadP12Certificate();
        const trustStore = this._loadTrustStore();

        return {
            key: this._getPrivateKey(p12),
            cert: this._getCertificate(p12),
            ca: trustStore,
            passphrase: this.config.p12Password,
            rejectUnauthorized: true,
        };
    }

    _loadP12Certificate() {
        const p12Buffer = fs.readFileSync(this.config.p12Path);
        const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString("binary"), false);
        return forge.pkcs12.pkcs12FromAsn1(p12Asn1, this.config.p12Password);
    }

    _loadTrustStore() {
        const certs = [];
        if (this.config.caPath) {
            const caData = fs.readFileSync(this.config.caPath, "utf8");
            const caCerts = this._parsePemCertificates(caData);
            certs.push(...caCerts.map((cert) => forge.pki.certificateToPem(cert)));
        }
        return certs;
    }

    _parsePemCertificates(pemData) {
        const regex = /-----BEGIN CERTIFICATE-----[^-----]+-----END CERTIFICATE-----/g;
        const matches = pemData.match(regex) || [];
        return matches.map((match) => forge.pki.certificateFromPem(match));
    }

    _getPrivateKey(p12) {
        const bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
        const bag = bags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
        if (!bag) throw new Error("Private key not found in PKCS12");
        return forge.pki.privateKeyToPem(bag.key);
    }

    _getCertificate(p12) {
        const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
        const bag = bags[forge.pki.oids.certBag]?.[0];
        if (!bag) throw new Error("Certificate not found in PKCS12");
        return forge.pki.certificateToPem(bag.cert);
    }

    _shouldRetry(error, retryCount) {
        if (retryCount >= this.config.maxRetries) return false;

        if (!error.response && error.code && [
            'ECONNRESET',
            'ECONNREFUSED',
            'ETIMEDOUT',
            'ECONNABORTED',
            'ENOTFOUND',
            'EPIPE',
        ].includes(error.code)) {
            return true;
        }

        if (error.response && error.response.status >= 500) {
            return true;
        }

        if (error.code === 'ECONNABORTED' && !error.response) {
            return true;
        }

        return false;
    }

    async _delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }


    async sendRequest(endpoint, data, schema, headers = {}, method = 'POST') {
        let lastError;

        if (schema) {
            validateRequest(schema, data);
        }

        for (let attempt = 1; attempt <= this.config.maxRetries + 1; attempt++) {
            try {
                const url = this._buildUrl(endpoint, data, method);
                const body = this._serializeBody(data, headers);
                const requestHeaders = this._buildHeaders(headers, body);

                const config = {
                    timeout: this.config.readTimeout,
                    headers: requestHeaders,
                };

                let response;
                if (method.toUpperCase() === 'GET') {
                    response = await this.httpClient.get(url, config);
                } else if (method.toUpperCase() === 'POST') {
                    response = await this.httpClient.post(url, body, config);
                } else if (method.toUpperCase() === 'PUT') {
                    response = await this.httpClient.put(url, body, config);
                } else {
                    throw new Error(`Unsupported HTTP method: ${method}`);
                }

                if (this.config.enableLogs) {
                    console.log(`Request succeeded on attempt ${attempt}: ${method} ${endpoint}`);
                }

                return response.data;

            } catch (error) {
                lastError = error;

                if (this._shouldRetry(error, attempt - 1)) {
                    const delay = this.config.retryDelay * Math.pow(2, attempt - 1); // экспоненциальная задержка
                    if (this.config.enableLogs) {
                        console.warn(`🔁 Retry ${attempt}/${this.config.maxRetries} after ${delay}ms. Error: ${error.message}`);
                    }
                    await this._delay(delay);
                    continue;
                } else {
                    break;
                }
            }
        }

        if (lastError.code === "ECONNABORTED") {
            throw new Error("Request timed out after retries");
        }
        if (lastError.response) {
            throw new Error(
                `Request failed after retries: ${lastError.response.status} - ${JSON.stringify(lastError.response.data)}`
            );
        }
        throw new Error(`Network error after retries: ${lastError.message}`);
    }

    async sendRequestPrint(
        endpoint,
        data,
        schema,
        headers = {},
        method = 'POST'
    ) {
        let lastError;

        if (schema) {
            validateRequest(schema, data);
        }

        for (let attempt = 1; attempt <= this.config.maxRetries + 1; attempt++) {
            try {
                const url = this._buildUrl(endpoint, data, method);
                const body = this._serializeBody(data, headers);
                const responseType = headers['X-Response-Type'] || 'json';
                const requestHeaders = this._buildHeaders(headers, body);

                // Извлекаем responseType из заголовков
                delete requestHeaders['X-Response-Type']; // ❗ удаляем, чтобы не отправлять

                const config = {
                    timeout: this.config.readTimeout,
                    headers: requestHeaders,
                    responseType,
                };

                let response;
                if (method.toUpperCase() === 'GET') {
                    response = await this.httpClient.get(url, config);
                } else if (method.toUpperCase() === 'POST') {
                    response = await this.httpClient.post(url, body, config);
                } else if (method.toUpperCase() === 'PUT') {
                    response = await this.httpClient.put(url, body, config);
                } else {
                    throw new Error(`Unsupported HTTP method: ${method}`);
                }

                if (this.config.enableLogs) {
                    console.log(`Request succeeded on attempt ${attempt}: ${method} ${endpoint}`);
                }

                return response.data;

            } catch (error) {
                lastError = error;

                if (this._shouldRetry(error, attempt - 1)) {
                    const delay = this.config.retryDelay * Math.pow(2, attempt - 1);
                    if (this.config.enableLogs) {
                        console.warn(`🔁 Retry ${attempt}/${this.config.maxRetries} after ${delay}ms. Error: ${error.message}`);
                    }
                    await this._delay(delay);
                    continue;
                } else {
                    break;
                }
            }
        }

        throw lastError;
    }

    _buildUrl(endpoint, data, method) {
        if (method.toUpperCase() !== 'GET') return endpoint;

        const queryString = new URLSearchParams(data).toString();
        return queryString ? `${endpoint}?${queryString}` : endpoint;
    }

    _generateClientSecret() {
        let result = '';
        const bytes = crypto.randomBytes(40);

        for (let i = 0; i < 40; i++) {
            const randomIndex = bytes[i] % ALLOWED_CHARACTERS.length;
            result += ALLOWED_CHARACTERS[randomIndex];
        }
        return result;
    }

    _serializeBody(data, headers) {
        if (data == null) {
            return undefined;
        }
        const contentType = Object.keys(headers)
            .find(key => key.toLowerCase() === 'content-type');

        if (contentType && headers[contentType] === 'application/json') {
            return JSON.stringify(data);
        }
        if (contentType && headers[contentType] === 'application/x-www-form-urlencoded') {
            return querystring.stringify(data);
        }
        if (data instanceof FormData || typeof data === 'string' || data instanceof Buffer) {
            return data;
        }
        return JSON.stringify(data);
    }

    _buildHeaders(headers, body) {
        const hasContentType = Object.keys(headers).some(key => key.toLowerCase() === 'content-type');
        const requestHeaders = { ...headers };

        if (!hasContentType) {
            if (body instanceof FormData) {
            } else if (typeof body === 'string' && body.startsWith('{')) {
                requestHeaders['Content-Type'] = 'application/json';
            } else {
                requestHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
            }
        }

        requestHeaders['User-Agent'] = 'SberApiSDK_NodeJs';

        return requestHeaders;
    }

    _splitJwt(jwt) {
        const blocks = jwt.split('.');
        if (blocks.length !== 3) {
            throw new Error('Invalid format. Expected three parts separated by dots.');
        }
        return blocks;
    }

    _decodeBase64Url(base64UrlEncodedString) {
        let base64 = base64UrlEncodedString.replace(/-/g, '+').replace(/_/g, '/');
        const padLength = (4 - (base64.length % 4)) % 4;
        base64 += '='.repeat(padLength);
        return Buffer.from(base64, 'base64').toString('utf-8');
    }

    async getAccessToken(authorizationReq) {
        authorizationReq.grant_type = "authorization_code";
        return this.sendRequest("/ic/sso/api/oauth/token", authorizationReq, authorizationReqSchema, {
            "Content-Type": "application/x-www-form-urlencoded"
        });
    }

    async getRefreshToken(refreshTokenReq) {
        refreshTokenReq.grant_type = "refresh_token";
        return this.sendRequest("/ic/sso/api/oauth/token", refreshTokenReq, refreshTokenReqSchema, {
            "Content-Type": "application/x-www-form-urlencoded"
        });
    }

    async getRevokeToken(accessToken, revokeTokenReq) {
        if (!accessToken) {
            throw new Error("AccessToken не передан или равен null/undefined");
        }
        return this.sendRequest("/ic/sso/api/v2/oauth/revoke", revokeTokenReq, revokeTokenReqSchema, {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/x-www-form-urlencoded"
        });
    }

    async getChangeClientSecret(accessToken, refreshClientSecretRq) {
        refreshClientSecretRq.access_token = accessToken
        refreshClientSecretRq.new_client_secret = this._generateClientSecret()
        const response = await this.sendRequest("/ic/sso/api/v1/change-client-secret", refreshClientSecretRq, changeClientSecretSchema, {
            Authorization: `Bearer ${accessToken}`,
            "Content-Type": "application/x-www-form-urlencoded"
        });

        return {
            clientSecretExpiration: response.clientSecretExpiration,
            new_client_secret: refreshClientSecretRq.new_client_secret
        }

        //Добавить в ответ new_client_secret
    }

    async getUserInfo(accessToken) {
        try {
            const encodedResponse = await this.sendRequest("/ic/sso/api/v2/oauth/user-info", null, null, {
                Authorization: `Bearer ${accessToken}`,
            }, 'GET');

            const payload = this._splitJwt(encodedResponse)[1];
            const decodedPayload = this._decodeBase64Url(payload);

            return {
                userInfoBodyResponse: JSON.parse(decodedPayload),
                jwt: encodedResponse
            };
        } catch (error) {
            throw new Error(`Failed to get user info: ${error.message}`);
        }
    }
}

function validateRequest(schema, data) {
    const { error } = schema.validate(data, { abortEarly: false });
    if (error) {
        const errorMessages = error.details.map((err) => ({
            field: err.context.key,
            message: err.message,
        }));
        throw new Error(`Validation failed:\n${JSON.stringify(errorMessages, null, 2)}`);
    }
}

export default ApiClient;
