const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM  = 'aes-256-gcm';
const IV_LENGTH  = 12;  // 96-bit IV — khuyến nghị cho GCM
const TAG_LENGTH = 16;  // 128-bit auth tag

function getValidatedKey() {
    const key = process.env.ENCRYPTION_KEY;

    if (!key) {
        throw new Error('Biến môi trường ENCRYPTION_KEY chưa được thiết lập.');
    }

    const keyBuffer = Buffer.from(key, 'hex');

    if (keyBuffer.length !== 32) {
        throw new Error(
            `ENCRYPTION_KEY phải là chuỗi hex 64 ký tự (32 bytes). Nhận được ${keyBuffer.length} bytes.`
        );
    }

    return keyBuffer;
}

function encrypt(text) {
    if (!text) return null;

    try {
        const key = getValidatedKey();
        const iv  = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

        const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        const authTag   = cipher.getAuthTag();

        return [
            iv.toString('hex'),
            authTag.toString('hex'),
            encrypted.toString('hex'),
        ].join(':');
    } catch (err) {
        console.error(`Mã hóa thất bại: ${err.message}`);
        return null;
    }
}

function decrypt(text) {
    if (!text) return null;

    try {
        const key   = getValidatedKey();
        const parts = text.split(':');

        if (parts.length !== 3) {
            throw new Error('Định dạng ciphertext không hợp lệ.');
        }

        const [ivHex, authTagHex, encryptedHex] = parts;
        const iv        = Buffer.from(ivHex, 'hex');
        const authTag   = Buffer.from(authTagHex, 'hex');
        const encrypted = Buffer.from(encryptedHex, 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag); 

        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (err) {
        console.error('Giải mã thất bại: ciphertext không hợp lệ hoặc đã bị giả mạo.');
        return null;
    }
}

module.exports = { encrypt, decrypt };