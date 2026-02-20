//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ReceivedJwtModel.swift
//  aduna-sdk
//

class ReceivedJwtModel: Codable {
    var app_info_jwt: String
    var scope: String

    init(app_info_jwt: String, scope: String) {
        
        self.app_info_jwt = app_info_jwt
        self.scope = scope
    }
}

class ClaimModel: Codable {
    var path: [String]
    var values: [String]
}
