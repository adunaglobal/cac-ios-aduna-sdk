# ADUNA SDK 
iOS structured XCFramework used for CAMARA Number Verification version 2 (NV2).  
Aduna's SDK fulfills the end-to-end flow of SIM-based Authentication. For this document "Aduna's SDK" will be referenced as "SDK". 


## Contents 
1. [Features](#features) 
2. [Development Requirements](#development-requirements) 
3. [Compatibility](#compatibility) 
4. [Installation](#installation) 
5. [Quick Start](#quick-start) 
6. [Developer Guide](#developer-guide) 
7. [Building from Source](#building-from-source) 
8. [Troubleshooting](#troubleshooting) 
9. [Privacy & Data Handling](#privacy--data-handling)
10. [Public Notice](#public-notice)
11. [Support & Contact](#support--contact) 
12. [Versioning](#versioning) 
13. [License](#license) 


## Features  

### General  

- Supports NV2 flows
- Detection of NV2 functionality from invocation URL
- Retrieval of Carrier's token from Carrier's Entitlement Server (ECS) 
- Returns encrypted carrier token to ASP app 
- Customizable Swift-UI based view according to carrier app needs 
- Supports configurable settings covering testing and production activities, appearance,and more. Configurable behavior via CAACSPOptions 
- SDK is localization-ready and supports all iOS localization mechanisms; language resources are not included and must be provided by the integrating application
- Logging and Analytics capabilities 


## Development Requirements 
- iOS 18.6+ 
- Xcode 16+ 
- Swift UI (compatible with UIKit and Storyboards via hosting controllers) 
 
 
## Setup Requirements 
- Apple carrier entitlements for the Carrier app, which allow the SDK to retrieve the carrier token
- Carrier handover HTML page, which must be opened in the Safari browser
- AASA file including the appropriate paths for invoking the Carrier app or App Clip
- Recommendation: add an App Clip to the Carrier app and include the SDK in the App Clip target


## Compatibility 
The SDK is designed to operate with Aduna release 3.8 onwards which implements the supported NV2 APIs. 


## Installation 

### Manual 
- Select your Carrier app target in Xcode 
- Open General → Frameworks, Libraries, and Embedded Content 
- Add the XCFramework distributed by Aduna. 

### Swift Package Manager 
Not available 

### CocoaPods 
Not available 


## Quick Start 

### Configuration & Initialization - SwiftUI
Through `CAACCSPOptions.Builder()`, `CAACCSPOptions` can be initiated to provide required data for each operation. 

```swift
let cspOptions = CAACCSPOptions.Builder() 
.addENVOptions(useFixedCarrierToken: false, 
    skipConsentScreen: false, 
    envAppearance: ENVAppearance(), 
    expInSeconds: 120,
    rCTThreshold: 600) 
.build() 

let appearance = ENVAppearance() 
appearance.text.cspName = "Aduna" 
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
    // ... addENVOptions as shown above
.addAnalyticsDelegate(caacAnalyticsDelegate: AnalyticsDelegate())
.build()
```

 
### Handling Invocation URLs 
The `CAACSDK` provides a static function `getOperationFromUrl(invocationUrl: URL, cspOptions: CAACCSPOptions)` that may return a `CAACOperation` depending whether it corresponds to any NV or another operation. 

```swift 
... 
(view) 
.onContinueUserActivity(NSUserActivityTypeBrowsingWeb){ userActivity in 
  if let invocationUrl = userActivity.webpageURL, 
     let operation = CAACSDK.getOperationFromUrl( 
        invocationUrl: invocationUrl, 
        cspOptions: cspOptions 
    ) { 
       self.caacOperation = operation 
  } 
} 
``` 

### Presenting the Operation UI 
If a `CAACOperation` exists, the `CAACView(caacOperation: operation)` can be presented to take over the flow of the operation. 
```swift 
... 
(view body) 
if let operation = self.caacOperation { 
  CAACView(caacOperation: operation, appearance: appearance) 
} 
... 
``` 

### Logging Options 
The SDK provides configurable logging levels for debugging and production use. 
```swift  
// The logging levels are none, error and full logging for debugging 
enum SDKLogLevel: Int, Comparable { 
    case none = 0 
    case error 
    case debug 
    
    static func < (lhs: SDKLogLevel, rhs: SDKLogLevel) -> Bool { 
        return lhs.rawValue < rhs.rawValue 
    } 
} 

enum SDKLogger {
  ...
    static var level: SDKLogLevel = { 
        return .debug // SET HERE THE LOG LEVEL: .none, .error, .debug 
    }() 

  ...
} 
``` 
Note: Change of the default log level .none requires rebuild of the SDK

## Documentation
For detailed usage instructions and integration scenarios, refer to: 
- **Developer Guide for Aduna SDK iOS**
- **Protocol Specification for NV 2 in iOS**
- **NV 2 Implementation Framework for iOS SDK**

 
## Building from Source 

### Manual build 
From the project root directory, run command: 
./build-helper.sh 
 
The generated XCFramework will be available at: 
./build/manual/ 
You can copy the output file into your CSP app project. 

### Input Url 
**NV 2.0 URL format**

```text
https://<carrier-app-domain-and-base-path>?app_info_jwt=<signed by the aggregator and includes the aggregator’s data and ASP app data>&scope=<NV2.X scope> 
```

## Troubleshooting 
This section lists common issues encountered when integrating the SDK and how to resolve them. 

--- 
### The operation is always `nil` 

**Problem**  
`CAACSDK.getOperationFromUrl(...)` returns `nil`. 

**Possible causes** 
- The invocation URL does not match a supported CSP operation 
- The URL is missing required query parameters (e.g. `scope`) 
- The operation was triggered on an unsupported device or environment 
 
**Resolution** 
- Verify that the invocation URL is complete and correctly URL-encoded 
- Test using a known valid sample URL 
- Ensure the operation is triggered on a physical iOS device if required 

--- 
### Nothing happens when opening the invocation URL 

**Problem**  
The app opens, but the SDK UI is not presented. 

**Possible causes** 
- `onContinueUserActivity` is not implemented or not reached 
- The returned `CAACOperation` is not retained 
- The `CAACView` is not rendered in the view hierarchy 

**Resolution** 
- Confirm that `NSUserActivityTypeBrowsingWeb` is handled 
- Store the returned operation in a `@State` or equivalent property 
- Ensure `CAACView` is conditionally presented when the operation is non-nil 

--- 
### The SDK behaves differently on a device and in the simulator 

**Problem**  
Behavior differs between simulator and physical device. 

**Possible cause** 
- Fetching of carrier token is not possible in simulator, because it is not attached to a physical network.
- App Clip card does not appear in simulators.

**Resolution** 
- Use the simulator with setting `Use Fixed Carrier Token` (useFixedCarrierToken) 
- There is a limitation on the App Clip card appearance in simulators.

--- 
### Build error: “Module not found” or “No such module” 

**Problem**  
Xcode reports that the SDK module cannot be found. 

**Possible causes** 
- The XCFramework is not added to the correct target 
- The framework is not embedded and signed 
 
**Resolution** 
- Ensure the XCFramework is added under **Frameworks, Libraries, and Embedded Content** 
- Set it to **Embed & Sign** 

---  
### UI does not match expected appearance 

**Problem**  
The SDK UI is displayed but does not reflect the configured appearance. 

**Possible causes** 
- Appearance configuration is created but not passed to `CAACView` 
- Default appearance values override custom settings 
 
**Resolution** 
- Ensure the same `ENVAppearance` instance is passed to the view 
- Apply appearance configuration before presenting the SDK UI 

--- 
### Logging does not produce output 

**Problem**  
No logs appear in the console. 

**Possible causes** 
- Logging level is set to `.none` 
- Logs are filtered out in the Xcode console 

**Resolution** 
- Set `SDKLogger.level = .debug` or `SDKLogger.level = .error` 
- Verify the correct subsystem and category are visible in the console 
- Avoid using `.debug` in production builds 

--- 
### App Clip does not trigger the SDK 

**Problem**  
The SDK is not invoked when launched via an App Clip URL. 

**Possible causes** 
- Associated Domains are not configured correctly in the Carrier app or App Clip target
- The AASA file does not include the required paths for invoking the Carrier app or App Clip
- The carrier handover HTML page is missing required metadata or invocation parameters
- The invocation URL is not opened in the Safari browser


- Apple carrier entitlements for the Carrier app, which allow the SDK to retrieve the carrier token
- Carrier handover HTML page, which must be opened in the Safari browser
- AASA file including the appropriate paths for invoking the Carrier app or App Clip


**Resolution** 
- Verify the `applinks:` configuration for both the Carrier app and App Clip targets
- Ensure the AASA file includes the correct paths and bundle identifiers
- Validate the carrier handover HTML page metadata and invocation URL format
- Confirm that the URL is opened in **Safari** (other browsers are not supported)
--- 


## Public Notice
This SDK is source-available and maintained by Aduna. Code contributions and GitHub issue submissions are not accepted. 

 
## Privacy & Data Handling 
The SDK evaluates device state and network-related information solely to determine whether an eligible CSP operation (such as NV) can be performed. 

Specifically: 
- No personal data is stored persistently by the SDK 
- All network communication and data transmission are initiated and controlled by the hosting application 


## Support & Contact 
Support is provided on a **best-effort basis**. 

 
## License 
See the "Aduna SDK Software License Agreement.pdf" file for details. 

