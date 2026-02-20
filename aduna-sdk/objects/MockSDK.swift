//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  MockSDK.swift
//  sdk
//

import Foundation


internal class MockSDK: CAACSDK{
    enum MockState {
        case loading
        case success
        case failure
    }
    
    private let wantedState: MockState
    
    init(wantedState: MockState) {
        self.wantedState = wantedState
        super.init(useFixedCarrierToken: true, expInSeconds: 120)
    }
    
    override func performNumberVerification() {}
}
