//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  CAACView.swift
//  aduna-sdk
//

import Foundation

import SwiftUI
import OSLog

var previewVcpState = "a6391c96-16b5-4ee7-b2bf-bbac7fdec474"

/**
 CAACView is the entry point for **ENV** .
 User is automatically guided to one of these operations depending on the ``CAACOperation`` returned
 from ``CAACSDK/getOperationFromUrl(invocationUrl:cspOptions:)``
 */
public struct CAACView: View {
    var caacOperation : CAACOperation
    
    @Environment(\.locale) var sdkLocale
    
    public init(caacOperation: CAACOperation) {
        self.caacOperation = caacOperation
    }
    
    public var body: some View {
        switch caacOperation {
        case let eNVOperation as ENVOperation:
            if eNVOperation.eNVCSPOptions.skipConsentScreen {
                ENVContentView()
                    .environment(\.locale, sdkLocale)
                    .environmentObject(eNVOperation.eNVCSPOptions.envAppearance)
                    .environmentObject(eNVOperation.sdk)
            } else if eNVOperation.sdk.uLinkModel?.performNumberVerification == true {
                ENVConsentView(eNVsdk: eNVOperation.sdk)
                    .environment(\.locale, sdkLocale)
                    .environmentObject(eNVOperation.eNVCSPOptions.envAppearance)
                    .environmentObject(eNVOperation.sdk)
            }
            else {
                ENVContentView()
                    .environment(\.locale, sdkLocale)
                    .environmentObject(eNVOperation.eNVCSPOptions.envAppearance)
                    .environmentObject(eNVOperation.sdk)
            }
        default:
            Text("Unknown Error")
        }
    }
}

#Preview("Default") {
    let appearance: ENVAppearance = {
        var ap = ENVAppearance()
        ap.text.cspName = "CSP Name"
        ap.text.sideSpacing = 10
        return ap
    }()

    let envCspOptions = ENVCSPOptions(
           useFixedCarrierToken: true,
           skipConsentScreen: false,
           envAppearance: appearance,
           expInSeconds: 100
       )
  
    let previewSdk: CAACSDK = {
        let sdk = CAACSDK()
        sdk.uLinkModel = ULinkModel(payload: nil, appCallbackUrl: URL(filePath: "https://adunaglobal.com"), state: "abdcef1234567890", appName: "APP", aspState: nil, performNumberVerification: true)
        return sdk
    }()

    let previewOperation = ENVOperation(
        sdk: previewSdk, eNVCSPOptions: envCspOptions
    )
    CAACView(caacOperation: previewOperation)
}



fileprivate extension URL {
    func valueOf(_ queryParameterName: String) -> String? {
        guard let url = URLComponents(string: self.absoluteString) else { return nil }
        return url.queryItems?.first(where: { $0.name == queryParameterName })?.value
    }
}
