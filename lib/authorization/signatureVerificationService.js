import { execFileSync } from 'child_process';
import { writeFileSync, unlinkSync, accessSync } from 'fs';
import { tmpdir, platform } from 'os';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

/**
 * Сервис проверки подписи JWT через Java + Bouncy Castle
 */
export default class SignatureVerificationService {
    /**
     * @param {string} certificatePath - путь к .cer файлу сертификата
     */
    constructor(certificatePath) {
        // Получаем __dirname в ES-модулях
        const __dirname = dirname(fileURLToPath(import.meta.url));

        // Путь к встроенному JAR
        this.jarPath = join(__dirname, '..', 'jars', 'signature-verifier.jar');

        if (!certificatePath) {
            throw new Error('Certificate path is required');
        }

        // Проверяем существование сертификата
        try {
            accessSync(certificatePath);
        } catch (err) {
            throw new Error(`Certificate file not found or not readable: ${certificatePath}`);
        }

        // Проверяем существование JAR
        try {
            accessSync(this.jarPath);
        } catch (err) {
            throw new Error(`Internal JAR not found: ${this.jarPath}. Make sure 'signature-verifier.jar' is placed in the 'jars/' folder.`);
        }

        // Проверяем, доступна ли команда java
        try {
            execFileSync('java', ['-version'], { stdio: 'ignore' });
        } catch (err) {
            throw new Error(
                'Java is not installed or not available in PATH. ' +
                'Please install Java 8+ to use this SDK.'
            );
        }

        this.certPath = certificatePath;
    }

    /**
     * Проверяет JWT подпись через Java-приложение
     * @param {string} jwt - JWT токен (в формате header.payload.signature)
     * @returns {boolean} - true, если подпись валидна
     * @throws {Error} - если подпись недействительна или произошла ошибка
     */
    verifyJwt(jwt) {
        if (!jwt || typeof jwt !== 'string') {
            throw new Error('JWT must be a non-empty string');
        }

        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format: expected 3 parts (header.payload.signature)');
        }

        // Создаём временный файл для JWT
        const tmpInputFile = join(tmpdir(), `jwt-${process.pid}-${Date.now()}.txt`);
        try {
            writeFileSync(tmpInputFile, jwt);

            // Выполняем Java-приложение
            const result = execFileSync(
                'java',
                [
                    '-cp', this.jarPath,
                    'ru.sberbank.sbbol.sberbusinessapi.services.SignatureVerificationCLI', // ← CLI, не Service!
                    this.certPath,
                    tmpInputFile
                ],
                { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
            );

            const output = result.trim();
            if (output === 'true') {
                return true;
            } else if (output === 'false') {
                throw new Error('Signature verification failed: invalid signature or certificate chain');
            } else {
                throw new Error(`Java verification error: ${output}`);
            }
        } catch (error) {
            const stderr = error.stderr?.toString() || '';
            const stdout = error.stdout?.toString() || '';
            const message = stderr || stdout || error.message;

            if (message.includes('InvalidJwtException')) {
                throw new Error(`Invalid JWT: ${message.substring(0, 500)}...`);
            } else if (message.includes('ClassNotFoundException')) {
                throw new Error(
                    'Java class not found. Make sure your JAR is a "fat jar" with all dependencies included.'
                );
            } else if (message.includes('ExceptionInInitializerError')) {
                throw new Error('Failed to initialize Bouncy Castle provider: ' + message);
            } else {
                throw new Error('Signature verification failed: ' + message.substring(0, 500));
            }
        } finally {
            // Удаляем временный файл
            try {
                unlinkSync(tmpInputFile);
            } catch (e) {
                // Игнорируем ошибку удаления
            }
        }
    }
}
