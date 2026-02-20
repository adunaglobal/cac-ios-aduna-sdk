//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVOperation.swift
//  aduna-sdk
//

class ENVOperation: CAACOperation{
    
    let eNVCSPOptions: ENVCSPOptions
    let sdk: CAACSDK
    
    init(sdk: CAACSDK, eNVCSPOptions: ENVCSPOptions) {
        self.eNVCSPOptions = eNVCSPOptions
        self.sdk = sdk
    }
}
