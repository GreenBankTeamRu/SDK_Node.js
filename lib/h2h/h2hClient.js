import AdmZip from 'adm-zip';

import ApiClient from '../authorization/client.js'
import validators from './validators.js';

const { certRequestReqSchema, certRequestReqEIOSchema, paymentReqSchema, payrollReqSchema } = validators;

export default class H2hClient {

    constructor(apiClient) {
        if (!(apiClient instanceof ApiClient)) {
            throw new TypeError('Expected an instance of ApiClient');
        }

        this.apiClient = apiClient;
    }

    async getDictionary(accessToken, name) {
        const response = await this.apiClient.sendRequest(
            '/fintech/api/v1/dicts',
            { name },
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );

        if (!response || !response.archive) {
            throw new Error(`Некорректный ответ от сервера: ${JSON.stringify(response)}`);
        }

        const unzippedContent = this._decodeAndUnzip(response.archive);

        return {
            name: response.name,
            content: unzippedContent
        };
    }

    async getClientInfo(accessToken) {
        return await this.apiClient.sendRequest(
            '/fintech/api/v1/client-info',
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getCrypto(accessToken) {
        return await this.apiClient.sendRequest(
            '/fintech/api/v1/crypto',
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getCryptoEio(accessToken) {
        return await this.apiClient.sendRequest(
            '/fintech/api/v1/crypto/eio',
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async certificateRequest(accessToken, certRequestReq) {
        return await this.apiClient.sendRequest(
            '/fintech/api/v1/crypto/cert-requests',
            certRequestReq,
            certRequestReqSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async certificateRequestEIO(accessToken, certRequestReqEIO) {
        return await this.apiClient.sendRequest(
            '/fintech/api/v1/crypto/cert-requests/eio',
            certRequestReqEIO,
            certRequestReqEIOSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async activateCertEIO(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/crypto/cert-requests/eio/${externalId}/activate`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async activateCert(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/crypto/cert-requests/${externalId}/activate`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async printCert(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/crypto/cert-requests/${externalId}/print`;

        return await this.apiClient.sendRequestPrint(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`,
                'X-Response-Type': 'arraybuffer'
            },
            'GET',
            'arraybuffer'
        );
    }

    async getCertState(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/crypto/cert-requests/${externalId}/state`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getCertStateEIO(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/crypto/cert-requests/eio/${externalId}/state`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }


    async createPayment(accessToken, paymentReq) {

        return await this.apiClient.sendRequest(
            "/fintech/api/v1/payments",
            paymentReq,
            paymentReqSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async getPayment(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/payments/${externalId}`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getPaymentDocState(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/payments/${externalId}/state`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getStatementSummary(accessToken, accountNumber, statementDate) {

        return await this.apiClient.sendRequest(
            "/fintech/api/v2/statement/summary",
            {accountNumber, statementDate},
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getStatementTransactionId(accessToken, id, accountNumber, operationDate) {

        return await this.apiClient.sendRequest(
            "/fintech/api/v2/statement/transactionId",
            {id, accountNumber, operationDate},
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getStatementTransactions(accessToken, accountNumber, statementDate, page, curFormat) {

        return await this.apiClient.sendRequest(
            "/fintech/api/v2/statement/transactions",
            { accountNumber, statementDate, page, curFormat},
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async createPayroll(accessToken, payrollReq) {

        return await this.apiClient.sendRequest(
            "/fintech/api/v1/payrolls",
            payrollReq,
            payrollReqSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async getPayroll(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/payrolls/${externalId}`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    async getPayrollState(accessToken, externalId) {
        const endpoint = `/fintech/api/v1/payrolls/${externalId}`;

        return await this.apiClient.sendRequest(
            endpoint,
            null,
            null,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'GET'
        );
    }

    _decodeAndUnzip(base64EncodedZip) {
        try {
            const decodedBuffer = Buffer.from(base64EncodedZip, 'base64');

            const zip = new AdmZip(decodedBuffer);
            const entries = zip.getEntries();

            let content = '';

            for (const entry of entries) {
                if (!entry.isDirectory) {
                    const fileData = entry.getData().toString('utf8');
                    content += fileData;
                }
            }

            return content;
        } catch (error) {
            throw new Error("Произошла ошибка при декодировании архива: ", { cause: error });
        }
    }
}
