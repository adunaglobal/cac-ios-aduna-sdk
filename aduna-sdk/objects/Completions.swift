//
// Copyright Aduna AB (2026)
// Licensed under the Aduna SDK Software License Agreement
//
//  Completions.swift
//  sdk
//
//  Created by Dimitris Kotronis on 10/10/23.
//

import Foundation

typealias VoidCompletionWithoutResult = () -> Void

typealias VoidResult = Result<Void, Error>
typealias VoidCompletion = (VoidResult) -> Void

typealias VoidCompletionWithCode = (VoidResult, String?) -> Void
typealias BooleanCompletion = (Bool) -> Void


typealias StringResult = Result<String, Error>
typealias StringCompletion = (StringResult) -> Void

typealias UrlResult = Result<URL, Error>
typealias UrlCompletion = (UrlResult) -> Void

