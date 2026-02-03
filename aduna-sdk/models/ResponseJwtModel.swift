//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ResponseJwtModel.swift
//  aduna-sdk
//
//  Created by Lilianna Georgouli on 25/7/25.
//

struct ResponseJwtModel: Encodable {
    var `protocol`: String
    var data: DataResponse
}

struct DataResponse: Encodable {
    var vp_token: [String:[String]]
}

struct JWTIssuerPayload: Encodable {
    let iss: String
    let vct: [String]
    let cnf: DeviceConfirmation
    let exp: Int
    let iat: Int
}

struct DeviceConfirmation: Encodable {
    let jwk: JWKRepresentation
}

struct JWKRepresentation: Encodable {
    let alg: String
    let kty: String
    let crv: String
    let x: String
    let y: String
    let use: String
}

struct JWTKeyBindingPayload: Encodable {
    let iat: Int
    let aud: String
    let nonce: String
    let encrypted_credential: String
    let consent_data_hash: String
    let state: String?
    let sd_hash: String
    let carrier_hint: String
}

struct TokenPayload: Codable {
    let temp_token: String
}
