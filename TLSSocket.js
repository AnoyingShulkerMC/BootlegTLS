import crypto from "node:crypto"
import EventEmitter from "node:events"
import { createConnection } from "node:net"
import { Duplex } from "node:stream"
import { HandshakeType, ContentType, ClientState, Ciphers } from "./constants.js"
const version = 0x0303
export default class TLSSocket extends EventEmitter {
  state = ClientState.Start

  expectBufferQueue = []
  payloadBuffer = Buffer.alloc(0)

  messageLoopFinished = true

  debug(msg) { this.emit("debug", msg) }
  constructor(host, port) {
    super()
    this.con = createConnection(port, host)
    this.con.on("data", d => {
      this.payloadBuffer = Buffer.concat([this.payloadBuffer, d])
      this.processExpectBufferQueue()
      if (this.messageLoopFinished) this.messageLoop()
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
    if (this.payloadBuffer.length >= 1) return this.messageLoop()
    this.messageLoopFinished = true
  }
  expectBuffer(length) {
    return new Promise((resolve) => {
      this.expectBufferQueue.push([length, resolve])
      this.processExpectBufferQueue()
    })
  }
  processExpectBufferQueue() {
    while (this.expectBufferQueue.length > 0 && this.expectBufferQueue[0][0] <= this.payloadBuffer.length) {
    console.log(this.payloadBuffer)
      var length = this.expectBufferQueue[0][0]
      var resolve = this.expectBufferQueue[0][1]
      resolve(this.payloadBuffer.subarray(0, length))
      this.payloadBuffer = this.payloadBuffer.subarray(length)
      this.expectBufferQueue.shift()
    }
  }
  sendClientHello() {
    console.log(Vector(Object.values(Ciphers), 2 ** 16 - 2))
    this.sendHandshakeMessage(HandshakeType.ClientHello, Buffer.concat([
      Buffer.from([0x3, 0x3]), // TLS Version
      generateRandom(), // Random number
      Vector([crypto.randomBytes(32)], 32), // Session ID
      Vector(Object.values(Ciphers), 2 ** 16 - 2), // Ciphers
      Vector([Buffer.alloc(1)], 255) // Compression Method
    ]))
  }
  sendHandshakeMessage(type, data) {
    var header = Buffer.alloc(4)
    header.writeUint8(type)
    header.writeUint16BE(data.length >> 8, 1)
    header.writeUint8(data.length & 255, 3)
    this.sendMessage(ContentType.Handshake, Buffer.concat([header, data]))
  }
  sendMessage(type, data) {
    var header = Buffer.alloc(5)
    header.writeUint8(type)
    header.writeUint16BE(version, 1)
    header.writeUint16BE(data.length, 3)
    console.log(Buffer.concat([header, data]).toString("hex"))
    this.con.write(header)
    this.con.write(data)
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
function Vector(elements, totalLength = 255) {
  var len = Math.ceil(Math.log2(totalLength + 1) / 8)
  var byteLength = elements.reduce((prev, cur) => {
    console.log(prev, (Buffer.isBuffer(cur) ? cur.length : Buffer.from(cur).length))
    return prev + (Buffer.isBuffer(cur) ? cur.length : Buffer.from(cur).length)
  }, 0)
  console.log(byteLength)
  var ret = Buffer.alloc(len)
  for (var i = 0; i < len; i++) ret.writeUint8((byteLength >> 8 * (len - i - 1)) & 255, i)
  for (var i of elements) ret = Buffer.concat([ret, Buffer.isBuffer(i) ? i : Buffer.from(i)])
  return ret
}
new TLSSocket("google.com", 443)