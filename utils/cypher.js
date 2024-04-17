const {
    encryption_private_key,
    encryption_private_iv,
    hash_salt
 } = require('./config.js');

const sha256 = require('sha256');
const crypto = require('crypto');
const algorithm = 'aes-256-cbc';

const hash = function (content){
    return sha256(content + hash_salt);
}

// encrypt the given content parameter using encryption_private_key as the encryption key
const encrypt = function (content) {
    const cipher = crypto.createCipheriv(algorithm, encryption_private_key, encryption_private_iv);

    // return encrypted content
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return encrypted
}

// decrypt the given content parameter using encryption_private_key as the encryption key
const decrypt = function (content) {
    const decipher = crypto.createDecipheriv(algorithm, encryption_private_key, encryption_private_iv);

    let decrypted = decipher.update(content, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted
}

exports.hash = hash;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
