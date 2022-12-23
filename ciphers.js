import crypto from "node:crypto"
import { HandshakeType, ContentType, ClientState, ExtensionType, SignatureAlgorithm, HashAlgorithm } from "./constants.js"
import TLSSocket from "./TLSSocket.js"

export const Ciphers = {
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": [
    0,
    158
  ],
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": [
    0,
    159
  ],
  "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": [
    0,
    170
  ],
  "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": [
    0,
    171
  ],
  /*"TLS_AES_128_GCM_SHA256": [
    19,
    1
  ],
  "TLS_AES_256_GCM_SHA384": [
    19,
    2
  ],
  "TLS_CHACHA20_POLY1305_SHA256": [
    19,
    3
  ],
  "TLS_AES_128_CCM_SHA256": [
    19,
    4
  ],
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": [
    192,
    43
  ],
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": [
    192,
    44
  ],
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": [
    192,
    47
  ],
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": [
    192,
    48
  ],*/
  "TLS_DHE_RSA_WITH_AES_128_CCM": [
    192,
    158
  ],
  "TLS_DHE_RSA_WITH_AES_256_CCM": [
    192,
    159
  ],
  /*"TLS_DHE_PSK_WITH_AES_128_CCM": [
    192,
    166
  ],
  "TLS_DHE_PSK_WITH_AES_256_CCM": [
    192,
    167
  ],
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": [
    204,
    168
  ],
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": [
    204,
    169
  ],
  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": [
    204,
    170
  ],
  "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256": [
    204,
    172
  ],
  "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256": [
    204,
    173
  ],
  "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256": [
    208,
    1
  ],
  "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384": [
    208,
    2
  ],
  "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256": [
    208,
    5
  ]*/
}

/**
 * @typedef {Object} CipherSuite
 * @property {Function} keyExchange
 * @property {string} hmac
 * @property {number} macKeyLength
 * @property {number} ivLength
 * @property {number} keyLength
 */
export const CipherInfo = {
  "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": {
    keyExchange: dheWithSignature,
    hmac: "sha256",
    macKeyLength: 32,
    ivLength: 4,
    keyLength: 32,
    encrypt(iv, socket) { }
  },
  "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": {
    keyExchange: dheWithSignature,
    hmac: "sha384",
    ivLength: 4,
    keyLength: 32,
    macKeyLength: 48
  },
  /*"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": {
    keyExchange: "dhe_psk",
    cipher: "aes-128-gcm",
    hmac: "sha256",
    type: "block"
  },
  "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": {
    keyExchange: "dhe_psk",
    cipher: "aes-256-gcm",
    hmac: "sha384",
    type: "block"
  },
  "TLS_AES_128_GCM_SHA256": [
    19,
    1
  ],
  "TLS_AES_256_GCM_SHA384": [
    19,
    2
  ],
  "TLS_CHACHA20_POLY1305_SHA256": [
    19,
    3
  ],
  "TLS_AES_128_CCM_SHA256": [
    19,
    4
  ],
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {
    keyExchange: "ecdhe_ecdsa",
    cipher: "aes-128-gcm",
    hmac: "sha256",
    type: "block"
  },
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {
    keyExchange: "ecdhe_ecdsa",
    cipher: "aes-256-gcm",
    hmac: "sha384",
    type: "block"
  },
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
    keyExchange: "dhe_rsa",
    cipher: "aes-128-gcm",
    hmac: "sha256",
    type: "block"
  },
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
    keyExchange: "ecdhe_rsa",
    cipher: "aes-256-gcm",
    hmac: "sha384",
    type: "block"
  },*/
  "TLS_DHE_RSA_WITH_AES_128_CCM": {
    keyExchange: "dhe_rsa",
    cipher: "aes-128-ccm",
    type: "block"
  },
  "TLS_DHE_RSA_WITH_AES_256_CCM": {
    keyExchange: "dhe_rsa",
    cipher: "aes-256-ccm",
    type: "block"
  },
  /*"TLS_DHE_PSK_WITH_AES_128_CCM": {
    keyExchange: "dhe_psk",
    cipher: "aes-256-ccm",
    hmac: null
  },
  "TLS_DHE_PSK_WITH_AES_256_CCM": {
    keyExchange: "dhe_psk",
    cipher: "aes-256-ccm",
    hmac: null
  },
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {
    keyExchange: "ecdhe_rsa",
    cipher: "chacha20-poly1305",
    hmac: "sha256"
  },
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": {
    keyExchange: "ecdhe_ecdsa",
    cipher: "chacha20-poly1305",
    hmac: "sha256"
  },
  "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {
    keyExchange: "dhe_rsa",
    cipher: "chacha20-poly1305",
    hmac: "sha256"
  },
  "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256": {
    keyExchange: "ecdhe_psk",
    cipher: "chacha20-poly1305",
    hmac: "sha256"
  },
  "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256": {
    keyExchange: "dhe_psk",
    cipher: "chacha20-poly1305",
    hmac: "sha256"
  },
  "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256": {
    keyExchange: "ecdhe_psk",
    cipher: "aes-128-gcm",
    hmac: "sha256"
  },
  "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384": {
    keyExchange: "ecdhe_psk",
    cipher: "aes-256-gcm",
    hmac: "sha384"
  },
  "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256": {
    keyExchange: "ecdhe_psk",
    cipher: "aes-128-ccm",
    hmac: "sha256"
  },*/
}

function aeadBlock(nonce, content, authTag) {
  return Buffer.concat([nonce, content, authTag])
}

function dheWithSignature(data, socket) {

  var primeLength = data.readUint16BE()
  var offset = 2
  var prime = data.subarray(offset, offset += primeLength)
  var generatorLength = data.readUint16BE(offset)
  var generator = data.subarray(offset += 2, offset += generatorLength)
  var publicLength = data.readUint16BE(offset)
  var publicKey = data.subarray(offset += 2, offset += publicLength)
  var keyExchange = crypto.createDiffieHellman(prime, generator)
  var hashAlgorithm = HashAlgorithm[data.readUint8(offset)]
  offset += 1
  var signatureAlgorithm = SignatureAlgorithm[data.readUint8(offset)];
  offset += 1
  console.log(hashAlgorithm, signatureAlgorithm)
  var signatureLength = data.readUint16BE(offset)
  var verify = crypto.createVerify(hashAlgorithm)
  offset += 2
  verify.update(Buffer.concat([socket.clientRandom, socket.serverRandom, data.subarray(0, offset - 4)]))
  var result = verify.verify(socket.certificates[0].publicKey, data.subarray(offset, offset + signatureLength))
  if(!result) throw new Error("Bad signature")
  keyExchange.generateKeys()
  socket.preMasterSecret = keyExchange.computeSecret(publicKey)
  var keyExchangePacket = Buffer.alloc(2)
  keyExchangePacket.writeUint16BE(keyExchange.getPublicKey().length)
  socket.sendHandshakeMessage(HandshakeType.ClientKeyExchange, Buffer.concat([keyExchangePacket, keyExchange.getPublicKey()]))
}

function aesGCMEncrypt(byteSize) {
  /**
   * @param {Buffer} buffer
   * @param {number} type
   * @param {TLSSocket} socket
   */
  return (buffer, type, socket) => {
    var implicitNonce = socket.clientWriteIV
    var explicitNonce = crypto.randomBytes(8)
    var cipher = crypto.createCipheriv(`aes-${byteSize}-gcm`, socket.clientWriteKey, Buffer.concat([implicitNonce, explicitNonce]))
    var aad = Buffer.alloc(3)
    aad.writeUint16BE((socket.clientSequence >> 8) && 65535)
    aad.writeUint8(socket.clientSequence & 255)
    cipher.setAAD(Buffer.concat([aad, ]))
  }
}