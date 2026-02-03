//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVCSPOptions.swift
//  aduna-sdk
//
//  Created by Kotronis Dimitrios on 29/11/24.
//

class ENVCSPOptions {
    let useFixedCarrierToken: Bool
    let skipConsentScreen: Bool
    let envAppearance: ENVAppearance
    let expInSeconds: Int
    
    init(useFixedCarrierToken:Bool, skipConsentScreen: Bool, envAppearance: ENVAppearance, expInSeconds: Int) {
        self.useFixedCarrierToken = useFixedCarrierToken
        self.skipConsentScreen = skipConsentScreen
        self.envAppearance = envAppearance
        self.expInSeconds = expInSeconds
    }
    
}
