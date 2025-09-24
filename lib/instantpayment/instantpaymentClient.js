import ApiClient from "../authorization/client.js";
import validators, {paymentInvoiceFromAnyRequestSchema} from './validators.js'

const { paymentInvoiceReqSchema, paymentInvoiceBudgetReqSchema, paymentInvoiceAnyReqSchema } = validators;

/**
 * Типы криптопрофилей
 * @enum {string}
 */
const CryptoprofileType = {
    SMS: 'SMS',
    TOKEN: 'TOKEN'
};

export default class InstantpaymentClient {

    constructor(apiClient) {
        if (!(apiClient instanceof ApiClient)) {
            throw new TypeError('Expected an instance of ApiClient');
        }

        this.apiClient = apiClient;
    }

    async getPaymentInvoice(accessToken, paymentInvoiceReq) {
        const response = await this.apiClient.sendRequest(
            '/fintech/api/v1/payments/from-invoice',
            paymentInvoiceReq,
            paymentInvoiceReqSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async getPaymentInvoiceBudget(accessToken, paymentInvoiceBudgetReq) {
        const response = await this.apiClient.sendRequest(
            '/fintech/api/v1/payments/from-invoice-budget',
            paymentInvoiceBudgetReq,
            paymentInvoiceBudgetReqSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async getPaymentInvoiceAny(accessToken, paymentInvoiceAnyReq) {
        const response = await this.apiClient.sendRequest(
            '/fintech/api/v1/payments/from-invoice-any',
            paymentInvoiceAnyReq,
            paymentInvoiceFromAnyRequestSchema,
            {
                Authorization: `Bearer ${accessToken}`
            },
            'POST'
        );
    }

    async getPaymentState(accessToken, externalId) {
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

    /**
     * Строит URL для оплаты
     *
     * @param {string} externalId - Уникальный идентификатор платежа
     * @param {string} backUrl - URL для возврата после оплаты
     * @param {CryptoprofileType} cryptoprofileType - Тип аутентификации (SMS или TOKEN)
     * @param {string|null|undefined} host - Опциональный кастомный хост
     * @param {boolean} isProd - Признак продакшн-среды
     * @returns {string} Полный URL для оплаты
     * @throws {Error} Если cryptoprofileType некорректен
     */
    buildPaymentUrl(externalId, backUrl, cryptoprofileType, host, isProd) {
        this.validate(cryptoprofileType);

        let konturBankUrl = null;

        if (!host || host.trim() === '') {
            if (isProd) {
                konturBankUrl = cryptoprofileType === CryptoprofileType.SMS
                    ? 'https://sbi.sberbank.ru:9443'  // PROM_SMS_HOST
                    : 'http://localhost:28016'; // PROM_TOKEN_HOST (в данном случае одинаковый хост)
            } else {
                konturBankUrl = 'https://efs-sbbol-ift-web.testsbi.sberbank.ru:9443'; // TEST_HOST
            }
        } else {
            konturBankUrl = host;
        }

        // Экранируем параметры URL
        const encodedExternalId = encodeURIComponent(externalId);
        const encodedBackUrl = encodeURIComponent(backUrl);

        return `${konturBankUrl}/ic/ufs/rpp-light/index.html#/payment-creator/${encodedExternalId}?backUrl=${encodedBackUrl}`;
    }

    /**
     * Валидация типа криптопрофиля
     * @param {string} type
     * @throws {Error}
     */
    validate(type) {
        if (!type || (type !== CryptoprofileType.SMS && type !== CryptoprofileType.TOKEN)) {
            throw new Error(`Invalid cryptoprofileType: ${type}. Must be 'SMS' or 'TOKEN'.`);
        }
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

}
