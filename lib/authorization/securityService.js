import crypto from "crypto";

export default class SecurityService {
    /**
     * Генерирует PKCE Code Verifier длиной 32 байта (43 символа в base64url)
     * Это соответствует 32 байтам случайных данных → base64url без паддинга.
     * @returns {string} codeVerifier в формате base64url
     */
    generatePKCECodeVerifier() {
        const randomBytes = crypto.randomBytes(32);
        return this.base64UrlEncode(randomBytes);
    }

    /**
     * Генерирует PKCE Code Challenge из переданного code_verifier с использованием SHA-256.
     * @param {string} codeVerifier - строка, полученная из generatePKCECodeVerifier()
     * @returns {string} codeChallenge в формате base64url
     */
    generatePKCECodeChallenge(codeVerifier) {
        const hash = crypto
            .createHash('sha256')
            .update(codeVerifier, 'utf8')
            .digest();
        return this.base64UrlEncode(hash);
    }

    /**
     * Вспомогательный метод для кодирования в base64url (без паддинга)
     * @param {Buffer} buffer - данные для кодирования
     * @returns {string} закодированная строка в формате base64url
     */
    base64UrlEncode(buffer) {
        return buffer
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    }
}