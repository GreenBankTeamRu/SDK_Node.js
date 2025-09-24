import { URL, URLSearchParams } from 'url';

/**
 * Правила маскирования по типу
 */
const MASKING_RULES = {
    default: (value) => '****',
    email: (value) => {
        if (!value || value.length <= 4) return '****';
        return '****' + value.substring(4);
    },
    account: (value) => {
        const digits = value.replace(/[^0-9]/g, '');
        if (digits.length <= 6) return '****';
        return digits.substring(0, 8) + '*******' + digits.slice(-4);
    },
    phone: (value) => {
        const digits = value.replace(/[^0-9]/g, '');
        if (digits.length <= 4) return '****';
        return digits[0] + '****' + digits.slice(-2);
    },
    number: () => '****',
};

/**
 * Сопоставление полей (ключей) с типами маскирования
 */
const FIELD_MASKING_TYPES = {
    'Authorization': 'default',
    'authorization': 'default',
    'X-Auth-Token': 'default',
    'x-auth-token': 'default',

    'client_secret': 'default',
    'password': 'default',
    'access_token': 'default',
    'refresh_token': 'default',
    'token': 'default',
    'cert': 'default',
    'new_client_secret': 'default',
    'authPersonName': 'default',
    'lastName': 'default',
    'middleName': 'default',
    'purpose': 'default',
    'paymentPurpose': 'default',
    'archive': 'default',
    'payerName': 'default',
    'payeeName': 'default',
    'inn': 'default',
    'payerInn': 'default',
    'payeeInn': 'default',
    'INN': 'default',
    'orgTaxNumber': 'default',
    'authPersonTelfax': 'default',
    'id_token': 'default',

    'corrAccountNumber': 'account',
    'accountNumber': 'account',
    'payerAccount': 'account',
    'payeeAccount': 'account',
    'payeeBankCorrAccount': 'account',
    'payerBankCorrAccount': 'account',
    'account': 'account',

    'email': 'email',
    'phone_number': 'phone',
    'amount': 'number',
    'serialNumber': 'default'
};

/**
 * Эндпоинты, которые НЕ нужно логировать
 */
const EXCLUDES_LOG_URI = [
    '/v1/client-info',
    '/fintech/api/v1/dicts'
];

/**
 * Проверяет, нужно ли исключить логирование для URL
 */
function shouldExcludeLogging(url, baseURL) {
    try {
        const fullUrl = new URL(url, baseURL);
        const path = fullUrl.pathname;
        return EXCLUDES_LOG_URI.some(excluded => path.includes(excluded));
    } catch (e) {
        return false;
    }
}

/**
 * Маскирует заголовки
 */
function maskHeaders(headers) {
    const masked = {};
    for (const [key, value] of Object.entries(headers || {})) {
        if (FIELD_MASKING_TYPES[key]) {
            const type = FIELD_MASKING_TYPES[key];
            const maskFn = MASKING_RULES[type] || MASKING_RULES.default;
            masked[key] = maskFn(String(value));
        } else {
            masked[key] = value;
        }
    }
    return masked;
}

/**
 * Маскирует URL (параметры запроса)
 */
function maskUrl(url, params = {}, baseURL) {
    try {
        const urlObj = new URL(url, baseURL);
        const searchParams = new URLSearchParams(urlObj.search);

        for (const [key, value] of searchParams) {
            if (FIELD_MASKING_TYPES[key]) {
                const decoded = decodeURIComponent(value);
                const masked = MASKING_RULES[FIELD_MASKING_TYPES[key]](decoded);
                searchParams.set(key, encodeURIComponent(masked));
            }
        }

        urlObj.search = searchParams.toString();
        return urlObj.toString();
    } catch (e) {
        return url;
    }
}

/**
 * Маскирует тело запроса/ответа в зависимости от Content-Type
 */
function maskBody(body, contentType) {
    if (!body || typeof body === 'object' && Object.keys(body).length === 0) return body;

    const type = (contentType || '').toLowerCase();

    if (isJwt(body)) {
        return "*****"
    }

    if (type.includes('application/json')) {
        return maskJsonBody(body);
    }

    if (type.includes('application/x-www-form-urlencoded')) {
        return maskUrlEncodedBody(body);
    }

    if (typeof body === 'string') {
        if (body.trim().startsWith('{')) {
            return maskJsonBody(body);
        }
        if (body.includes('=') && body.includes('&')) {
            return maskUrlEncodedBody(body);
        }
    }

    return body;
}

/**
 * Маскирует JSON-объект рекурсивно
 */
function maskJsonBody(body) {
    try {
        const obj = typeof body === 'string' ? JSON.parse(body) : body;
        const maskedObj = deepMaskObject(obj);
        return JSON.stringify(maskedObj);
    } catch (e) {
        console.warn('Failed to parse JSON for masking:', e.message);
        return body;
    }
}

/**
 * Рекурсивно маскирует объект по ключам
 */
function deepMaskObject(obj) {
    if (typeof obj !== 'object' || obj === null) return obj;

    if (Array.isArray(obj)) {
        return obj.map(item => deepMaskObject(item));
    }

    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        if (FIELD_MASKING_TYPES[key]) {
            const type = FIELD_MASKING_TYPES[key];
            const maskFn = MASKING_RULES[type] || MASKING_RULES.default;
            result[key] = maskFn(String(value));
        } else {
            result[key] = deepMaskObject(value);
        }
    }
    return result;
}

/**
 * Маскирует x-www-form-urlencoded строку
 */
function maskUrlEncodedBody(body) {
    const pairs = body.split('&');
    return pairs.map(pair => {
        const [key, value] = pair.split('=', 2);
        if (!value) return pair;

        try {
            const decodedKey = decodeURIComponent(key);
            const decodedValue = decodeURIComponent(value);

            if (FIELD_MASKING_TYPES[decodedKey]) {
                const type = FIELD_MASKING_TYPES[decodedKey];
                const maskFn = MASKING_RULES[type] || MASKING_RULES.default;
                const masked = maskFn(decodedValue);
                return `${key}=${encodeURIComponent(masked)}`;
            }
        } catch (e) {
            // ignore
        }
        return pair;
    }).join('&');
}

function isJwt(str) {
    if (typeof str !== 'string') return false;
    const parts = str.split('.');
    return parts.length === 3 && parts.every(part => /^[A-Za-z0-9_-]+$/.test(part));
}

export const MaskingInterceptor = {
    shouldExcludeLogging,
    maskHeaders,
    maskUrl,
    maskBody,
    // Экспортируем правила и поля, если нужно расширить
    MASKING_RULES,
    FIELD_MASKING_TYPES,
    EXCLUDES_LOG_URI,
};