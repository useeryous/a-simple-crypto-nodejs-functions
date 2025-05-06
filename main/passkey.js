const crypto = require('crypto');

function encrypt(plainText) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const algorithm = 'aes-256-cbc';
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encryptedData = cipher.update(plainText, 'utf8', 'hex');
  encryptedData += cipher.final('hex');
  return {
    iv: iv.toString('hex'),
    key: key.toString('hex'),
    encryptedData: encryptedData
  };
}

function decrypt(encryptedData, key, iv, algorithm = 'aes-256-cbc') {
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, 'hex'), Buffer.from(iv, 'hex'));
    let decryptedData = decipher.update(encryptedData, 'hex', 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
}

export default {
    encrypt,
    decrypt
}