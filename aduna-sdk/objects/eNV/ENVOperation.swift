//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVOperation.swift
//  aduna-sdk
//
//  Created by Kotronis Dimitrios on 29/11/24.
//

class ENVOperation: CAACOperation{
    
    let eNVCSPOptions: ENVCSPOptions
    let sdk: CAACSDK
    
    init(sdk: CAACSDK, eNVCSPOptions: ENVCSPOptions) {
        self.eNVCSPOptions = eNVCSPOptions
        self.sdk = sdk
    }
}
