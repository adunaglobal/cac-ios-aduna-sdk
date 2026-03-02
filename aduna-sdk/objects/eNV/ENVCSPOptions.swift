//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ENVCSPOptions.swift
//  aduna-sdk
//

class ENVCSPOptions {
    let useFixedCarrierToken: Bool
    let skipConsentScreen: Bool
    let envAppearance: ENVAppearance
    let expInSeconds: Int
    let rCTThreshold: Double
    
    init(useFixedCarrierToken:Bool, skipConsentScreen: Bool, envAppearance: ENVAppearance, expInSeconds: Int, rCTThreshold: Double) {
        self.useFixedCarrierToken = useFixedCarrierToken
        self.skipConsentScreen = skipConsentScreen
        self.envAppearance = envAppearance
        self.expInSeconds = expInSeconds
        self.rCTThreshold = rCTThreshold
    }
    
}
