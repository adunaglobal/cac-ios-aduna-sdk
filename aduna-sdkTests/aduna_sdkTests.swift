//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  aduna_sdkTests.swift
//  aduna-sdkTests
//
//  Created by Kotronis Dimitrios on 30/10/24.
//

import XCTest
@testable import aduna_sdk

final class aduna_sdkTests: XCTestCase {
    
    final let baseUrl = "https://ses.iot2.adunaglobal.net:15085"
    final let servicePath = "/ses/silentAuth2/v1/createAppToken"
    var sdk:CAACSDK?
    
    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    class AnalyticsDelegate: CAACAnalyticsDelegate {
        func eventReport(event: aduna_sdk.CAACAnalyticsEvent, properties: [String : Any]?) {
            print(event.rawValue)
        }
    }

    
    func testSdkSetup() throws {
        let url  = URL(string: "www.adunaglobal.com")!
                
        let options = CAACCSPOptions.Builder()
            .addENVOptions(useFixedCarrierToken: true,
                           skipConsentScreen: false,
                           envAppearance: ENVAppearance(),
                           expInSeconds: 120
            )
            .build()
        
        let operation = CAACSDK.getOperationFromUrl(invocationUrl: url, cspOptions: options)
        
        // View Part
        let appearance = ENVAppearance()
        appearance.text.cspName = "Aduna"
        
        if let caacOperation = operation {
            _ = CAACView(caacOperation: caacOperation)
        }
        
    }
    
    
    func testPerformanceExample() throws {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
    
}
