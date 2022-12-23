import crypto from "node:crypto"
import EventEmitter from "node:events"
import { createConnection } from "node:net"
import { Duplex } from "node:stream"
import { HandshakeType, ContentType, ClientState, ExtensionType } from "./constants.js"
import {Ciphers, CipherInfo } from "./ciphers.js"
const version = 0x0303
export default class TLSSocket extends EventEmitter {
  state = ClientState.Start

  expectBufferQueue = []
  payloadBuffer = Buffer.alloc(0)

  /** @type {Object} */
  cipherInfo = null

  clientSequence = 0
  serverSequence = 0

  serverMacKey = null
  clientMacKey = null
  serverWriteKey = null
  clientWriteKey = null
  serverWriteIV = null
  clientWriteIV = null

  encrypted = true
  /** @type {crypto.X509Certificate} */
  certificates = null
  /** @type {crypto.DiffieHellman} */
  keyExchange = null
  /** @type {Buffer} */
  masterSecret = null
  /** @type {Buffer} */
  preMasterSecret = null
  /** @type {Buffer} */
  clientRandom = null
  /** @type {Buffer} */
  serverRandom = null
  /** @type {crypto.Hash} */
  handshakeMessages = Buffer.alloc(0)
  ciphersOffered = [["sha256","rsa"]]

  messageLoopFinished = true

  debug(msg) { this.emit("debug", msg) }
  constructor(host, port) {
    super()
    this.con = createConnection(port, host)
    this.con.on("data", d => {
      this.payloadBuffer = Buffer.concat([this.payloadBuffer, d])
      if (this.messageLoopFinished) this.messageLoop()
      this.processExpectBufferQueue()
    })
    this.sendClientHello()
    this.messageLoop()
  }
  async messageLoop() {
    console.log("processing")
    this.messageLoopFinished = false;
    var message = {
      type: null,
      version: null,
      data: null
    }
    message.type = (await this.expectBuffer(1))[0]
    message.version = (await this.expectBuffer(2)).readUint16BE()
    var length = (await this.expectBuffer(2)).readUint16BE()
    message.data = await this.expectBuffer(length)
    console.log(message)
    this.parseMessage(message)
    if (this.payloadBuffer.length >= 1) return this.messageLoop()
    this.messageLoopFinished = true
  }

  parseMessage({ type, version, data }) {
    console.log(type)
    switch (type) {
      case ContentType.Handshake:
        var type = data.readUint8()
        var length = (data.readUint16BE(1) << 8) | data.readUint8(3)
        var content = data.subarray(4, 4 + length)
        this.parseHandshakeMessage({ type, data: content })
        this.handshakeMessages = Buffer.concat([this.handshakeMessages, data])
    }
    this.serverSequence++
  }
  parseHandshakeMessage({ type, data }) {
    switch (type) {
      case HandshakeType.ServerHello:
        var hello = parseServerHello(data)
        this.serverRandom = hello.random
        this.cipherInfo = {
          hmac: "sha256",
          ...CipherInfo[hello.cipherSuite]
        }
        break;
      case HandshakeType.Certificate:
        console.log(parseServerCert(data))
        this.certificates = parseServerCert(data)
        break;
      case HandshakeType.ServerKeyExchange:
        this.cipherInfo.keyExchange(data, this)
        this.masterSecret = PRF(this.preMasterSecret, "master secret", Buffer.concat([this.clientRandom, this.serverRandom]), this.cipherInfo.hmac, 48)
        console.log(this.masterSecret)
        console.log("The Master Secret is:", this.masterSecret.toString("hex"))
        var keyExpansion = PRF(this.masterSecret, "key expansion", Buffer.concat([this.clientRandom, this.serverRandom]), this.cipherInfo.hmac, 2 * (this.cipherInfo.keyLength + this.cipherInfo.ivLength + this.cipherInfo.macKeyLength))
        this.clientMacKey = keyExpansion.subarray(0, this.cipherInfo.macKeyLength)
        this.serverMacKey = keyExpansion.subarray(this.cipherInfo.macKeyLength, this.cipherInfo.macKeyLength * 2)
        this.clientWriteKey = keyExpansion.subarray(this.cipherInfo.macKeyLength * 2, this.cipherInfo.macKeyLength * 2 + this.cipherInfo.keyLength)
        this.serverWriteKey = keyExpansion.subarray(this.cipherInfo.macKeyLength * 2 + this.cipherInfo.keyLength, 2 * (this.cipherInfo.macKeyLength + this.cipherInfo.keyLength))
        this.clientWriteIV = keyExpansion.subarray(2 * (this.cipherInfo.macKeyLength + this.cipherInfo.keyLength), 2 * (this.cipherInfo.macKeyLength + this.cipherInfo.keyLength) + this.cipherInfo.ivLength)
        this.serverWriteIV = keyExpansion.subarray(2 * (this.cipherInfo.macKeyLength + this.cipherInfo.keyLength) + this.cipherInfo.ivLength, 2 * (this.cipherInfo.macKeyLength + this.cipherInfo.keyLength + this.cipherInfo.ivLength))
        console.log(keyExpansion, this.clientMacKey, this.serverMacKey, this.clientWriteKey, this.serverWriteKey, this.clientWriteIV, this.serverWriteIV)
        this.postClientFinished()

    }
  }

  postClientFinished() {
    this.sendMessage(ContentType.ChangeCipherSpec, Buffer.from([1]))
    this.encrypted = true
    var keyExpansion = PRF(this.masterSecret, "key expansion", Buffer.concat([this.clientRandom, this.serverRandom]), this.cipherInfo.hmac)
    var handshakeHash = crypto.createHash(this.cipherInfo.hmac)
    handshakeHash.update(this.handshakeMessages)
    
    this.sendHandshakeMessage(HandshakeType.Finished, PRF(this.masterSecret, "client finished", handshakeHash.digest(), this.cipherInfo.hmac, 12))
  }
  sendClientHello(sessionID = crypto.randomBytes(32), random = generateRandom(), ciphers = Object.values(Ciphers), compression = [Buffer.alloc(1)], extensions = [Extension(ExtensionType.SignatureAlgorithms, Vector(Buffer.from([4, 1]), 2 ** 16 - 2))]) {
    console.log(ciphers)
    this.clientRandom = random
    this.sendHandshakeMessage(HandshakeType.ClientHello, Buffer.concat([
      Buffer.from([0x3, 0x3]), // TLS Version
      random, // Random number
      Vector([sessionID], 32), // Session ID
      Vector(ciphers, 2 ** 16 - 2), // Ciphers
      Vector(compression, 255), // Compression Method,
      Vector(extensions, 2**16-1)
    ]))
  }
  sendHandshakeMessage(type, data) {
    var header = Buffer.alloc(4)
    header.writeUint8(type)
    header.writeUint16BE(data.length >> 8, 1)
    header.writeUint8(data.length & 255, 3)
    this.sendMessage(ContentType.Handshake, Buffer.concat([header, data]))
    this.handshakeMessages = Buffer.concat([this.handshakeMessages, header, data])
  }
  sendMessage(type, data) {
    var header = Buffer.alloc(5)
    header.writeUint8(type)
    header.writeUint16BE(version, 1)
    header.writeUint16BE(data.length, 3)
    console.log(Buffer.concat([header, data]).toString("hex"))
    this.con.write(header)
    this.con.write(data)
    this.clientSequence++
  }

  expectBuffer(length) {
    return new Promise((resolve) => {
      this.expectBufferQueue.push([length, resolve])
      this.processExpectBufferQueue()
    })
  }
  processExpectBufferQueue() {
    while (this.expectBufferQueue.length > 0 && this.expectBufferQueue[0][0] <= this.payloadBuffer.length) {
      var length = this.expectBufferQueue[0][0]
      var resolve = this.expectBufferQueue[0][1]
      resolve(this.payloadBuffer.subarray(0, length))
      this.payloadBuffer = this.payloadBuffer.subarray(length)
      this.expectBufferQueue.shift()
    }
  }
}
function generateRandom() {
  var time = Buffer.alloc(4)
  time.writeUint32BE(Math.floor(Date.now() / 1000))
  return Buffer.concat([
    time,
    crypto.randomBytes(28)
  ])
}
function Vector(data, totalLength = 255) {
  var elements = Array.isArray(data) ? data : [data]
  var len = Math.ceil(Math.log2(totalLength + 1) / 8)
  var byteLength = elements.reduce((prev, cur) => {
    //console.log(prev, (Buffer.isBuffer(cur) ? cur.length : Buffer.from(cur).length))
    return prev + (Buffer.isBuffer(cur) ? cur.length : Buffer.from(cur).length)
  }, 0)
  var ret = Buffer.alloc(len)
  for (var i = 0; i < len; i++) ret.writeUint8((byteLength >> 8 * (len - i - 1)) & 255, i)
  for (var i of elements) ret = Buffer.concat([ret, Buffer.isBuffer(i) ? i : Buffer.from(i)])
  return ret
}
function Extension(id, data) {
  var idBuffer = Buffer.alloc(2)
  idBuffer.writeUint16BE(id)
  return Buffer.concat([
    idBuffer,
    Vector(data, 2**16 - 1)
  ])
}
/**
 * 
 * @param {Buffer} data
 */
function parseServerHello(data) {
  console.log(data)
  var version = data.readUint16BE()
  var random = data.subarray(2, 34)
  var offset = 34
  var sessionIDLength = data.readUint8(offset)
  offset += 1
  console.log(sessionIDLength)
  var sessionID = data.subarray(offset, offset + sessionIDLength)
  offset += sessionIDLength
  // parsingCipherSuite
  var cipherSuiteBuffer = Array.from(data.subarray(offset, offset + 2))
  console.log(cipherSuiteBuffer)
  var cipherSuite = Object.keys(Ciphers).find(a => Ciphers[a].every((e, i) => cipherSuiteBuffer[i] == e) )
  offset += 2
  var compressionMethod = data[offset]
  offset += 1
  var extensionsOffset = offset
  console.log(offset, data.length)
  if (offset == data.length) return {
    version,
    random,
    sessionID,
    cipherSuite,
    extensions: {}
  }
  else { // parse Extensions
    var extensions = {}
    var extensionsLength = data.readUint16BE(offset)
    offset += 2
    while (offset - extensionsOffset < extensionsLength) {
      var extensionID = data.readUint16BE(offset)
      offset += 2
      var extensionDataLength = data.readUint16BE(offset)
      offset += 2
      var extensionData = data.subarray(offset, offset + extensionDataLength)
      extensions[Object.keys(Extension).find(a => Extension[a] == extensionID)] = extensionData
    }
    return {
      version,
      random,
      sessionID,
      cipherSuite,
      extensions
    }
  }
}
/**
 * 
 * @param {Buffer} data
 */
function parseServerCert(data) {
  var certsLength = (data.readUint16BE() << 8) | data.readUint8(2)
  var offset = 3
  var certificates = []
  while (offset - 3 < certsLength) {
    var certLength = (data.readUint16BE(offset) << 8) | data.readUint8(offset + 2)
    offset += 3
    certificates.push(new crypto.X509Certificate(data.subarray(offset, offset + certLength)))
    offset += certLength
  }
  return certificates
}
/**
 * 
 * @param {Buffer} secret
 * @param {string} label
 * @param {Buffer} seed
 */
function PRF(secret, label, seed, algorithm, length) {
  var S1 = secret.subarray(0, Math.ceil(secret.length / 2))
  var S2 = secret.subarray(secret.length - Math.ceil(secret.length / 2), secret.length)
  return P_hash(secret, Buffer.concat([Buffer.from(label), seed]), algorithm, length)
}
function P_hash(secret, seed, algorithm, length) {

  function A(i) {
    if (i == 0) return seed
    var hmac = crypto.createHmac(algorithm, secret)
    hmac.update(A(i - 1, algorithm))
    return hmac.digest()
  }
  var ret = Buffer.alloc(0)
  for (var i = 1; ret.length < length; i++) {
    var hmac = crypto.createHmac(algorithm, secret)
    hmac.update(Buffer.concat([A(1), seed]))
    ret = Buffer.concat([ret, hmac.digest()])
  }
  return ret.subarray(0, length)
}

new TLSSocket("localhost", 8000)