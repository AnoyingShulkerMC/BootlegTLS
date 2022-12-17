export const ContentType = {
  ChangeCipherSpec: 20,
  Alert: 21,
  Handshake: 22,
  ApplicationData: 23
}


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
  ],
  "TLS_DHE_RSA_WITH_AES_128_CCM": [
    192,
    158
  ],
  "TLS_DHE_RSA_WITH_AES_256_CCM": [
    192,
    159
  ],
  "TLS_DHE_PSK_WITH_AES_128_CCM": [
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
  ]
}

export const ClientState = {
  Start: 0,
  WaitSH: 1,
  WaitCert: 2,
  WaitSvrKeyExchange: 3
}

export const HandshakeType = {
  ClientHello: 1,
  ServerHello: 2,
  NewSessionTicket: 4,
  EndOfEarlyData: 5,
  EncryptedExtensions: 8,
  Certificate: 11,
  CertificateRequest: 13,
  CertificateVerify: 15,
  Finished: 20,
  KeyUpdate: 24,
  MessageHash: 254
}

export const ExtensionType = {
  ServerName: 0,
  MaxFragmentLength: 1,
  StatusRequest: 5,
  SupportedGroups: 10,
  SignatureAlgorithms: 13,
  UseSRTP: 14,
  Heartbeat: 15,
  ALPN: 16,
  SignedCertTimestamp: 18,
  ClientCertType: 19,
  ServerCertType: 20,
  Padding: 21,
  PreSharedKey: 41,
  EarlyData: 42,
  SupportedVersions: 43,
  Cookie: 44,
  PSKKeyExchangeModes: 45,
  CertificateAuthorities: 47,
  OldFilters: 48,
  PostHandshakeAuth: 49,
  SignatureAlgorithmsCert: 50,
  KeyShare: 51
}

export const AlertDescription = {
  CloseNotify: 0,
  Unexpected_Message: 10,
  BadRecordMac: 20,
  RecordOverflow: 22,
  HandshakeFailure: 40,
  BadCertificate: 42,
  UnsupportedCertificate: 43,
  CertificateRevoked: 44,
  CertificateExpired: 45,
  CertificateUnknown: 46,
  IllegalParameter: 47,
  UnknownCA: 48,
  AccessDenied: 49,
  DecodeError: 50,
  DecryptError: 51,
  ProtocolVersion: 70,
  InsufficientSecurity: 71,
  InternalError: 80,
  InappropiateFallback: 86,
  UserCanceled: 90,
  MissingExtension: 109,
  UnsupportedExtension: 110,
  UnrecognizedName: 112,
  BadCertificateStatusResponse: 113,
  UnknownPSKIdentity: 115,
  CertificateRequired: 116,
  NoApplicationProtocol: 120
}