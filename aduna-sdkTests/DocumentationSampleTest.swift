//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  DocumentationSampleTest.swift
//  aduna-sdkTests
//

import XCTest
import aduna_sdk
import SwiftUI

final class DocumentationSampleTest: XCTestCase {
    
    var caacOperation: CAACOperation?

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    class AnalyticsDelegate: CAACAnalyticsDelegate {
        func eventReport(event: aduna_sdk.CAACAnalyticsEvent, properties: [String : Any]?) {
            print(event.rawValue)
        }
    }
    
    struct SampleView: View {
        
        @State
        var caacOperation:CAACOperation?
        
        public var body: some View {
            return VStack {
                if let caacOperation = caacOperation  {
                    CAACView(caacOperation: caacOperation)
                } else {
                    Text("This is the CSP App.")
                }
            }
            .onOpenURL { url in
                self.handleInvocationUrl(invocationUrl: url)
            }
            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { userActivity in
                self.handleInvocationUrl(invocationUrl: userActivity.webpageURL)
            }
        }
        
        func handleInvocationUrl(invocationUrl: URL?) {
            let cspOptions = CAACCSPOptions.Builder()
                .addENVOptions(useFixedCarrierToken: false,
                               skipConsentScreen: false,
                               envAppearance: ENVAppearance(),
                               expInSeconds: 120
                )
                .addAnalyticsDelegate(caacAnalyticsDelegate: AnalyticsDelegate())
                .build()
            
            if let invocationUrl = invocationUrl,
               let operation =  CAACSDK.getOperationFromUrl(invocationUrl: invocationUrl,
                                                            cspOptions: cspOptions)
            {
                caacOperation = operation
            }
        }
    }
    
    func testExample() throws {
        var view = SampleView()
            
    }
    
    func customizeAppearanceExample(){
        let envAppearance = ENVAppearance()
        envAppearance.text.cspName = "My CSP"
        envAppearance.backgroundStyle = Color.yellow
        envAppearance.images.contentLogo = Image("logo")

    }

    
}
