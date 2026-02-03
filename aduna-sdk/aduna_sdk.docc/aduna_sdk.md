# ``aduna_sdk``

<!--@START_MENU_TOKEN@-->Summary<!--@END_MENU_TOKEN@-->

## Overview

This ADUNA SDK provides the a SwiftUI view ``CAACView`` and functions provision required data through ``CAACSDK`` and ``CAACCSPOptions``.

### Usage sample

```swift
import aduna_sdk

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
                           expInSeconds: 120)
            .build()
        
        if let invocationUrl = invocationUrl,
           let operation =  CAACSDK.getOperationFromUrl(invocationUrl: invocationUrl,
                                                        cspOptions: cspOptions)
        {
            caacOperation = operation
        }
    }
}
```

### Add analytics 

```swift
// Implement CAACAnalyticsDelegate
class AnalyticsDelegate: CAACAnalyticsDelegate {
    func eventReport(event: aduna_sdk.CAACAnalyticsEvent, properties: [String : Any]?) {
        print(event.rawValue)
    }
}
// Add delegate to builder
let cspOptions = CAACCSPOptions.Builder()
    // ...
    .addAnalyticsDelegate(caacAnalyticsDelegate: AnalyticsDelegate())
    .build()
```

### Customize appearance 
```swift
let envAppearance = ENVAppearance()
envAppearance.text.cspName = "My CSP"
envAppearance.backgroundStyle = Color.yellow
envAppearance.images.contentLogo = Image("logo")
```

## Topics

### Group

- <!--@START_MENU_TOKEN@-->``Symbol``<!--@END_MENU_TOKEN@-->
