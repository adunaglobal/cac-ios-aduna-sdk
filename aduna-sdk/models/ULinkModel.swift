//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  ULinkModel.swift
//  sdk
//
//  Created by Dimitris Kotronis on 16/10/23.
//  Modified by Lilianna Georgouli on 24/1/24.
//

class ULinkModel: NSObject {
    var payload:  [String : Any]?
    var appCallbackUrl: URL
    var state: String
    var appName: String
    var aspState: String?
    var performNumberVerification: Bool
    
    init(payload: [String: Any]?, appCallbackUrl: URL, state: String, appName: String, aspState: String?, performNumberVerification: Bool){
        
        self.payload = payload
        self.appCallbackUrl = appCallbackUrl
        self.state = state
        self.appName = appName
        self.aspState = aspState
        self.performNumberVerification = performNumberVerification
    }
}

