//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  Logger.swift
//  aduna-sdk
//

import OSLog

enum SDKLogLevel: Int, Comparable {
    case none = 0
    case error
    case debug
    
    static func < (lhs: SDKLogLevel, rhs: SDKLogLevel) -> Bool {
           return lhs.rawValue < rhs.rawValue
       }
}

enum SDKLogger {
    
    static let logger = Logger(subsystem: "com.adunaglobal.caac.ios.csp.sdk", category: "ENVSDK")

    static var level: SDKLogLevel = {
        return .debug      // SET HERE THE LOG LEVEL: .none, .error, .debug
    }()

    static func debug(_ message: String) {
        guard level >= .debug else { return }
        logger.debug("\(message, privacy: .public)")
    }
    
    static func error(_ message: String) {
        guard level >= .error else { return }
        logger.error("\(message, privacy: .public)")
    }
}
