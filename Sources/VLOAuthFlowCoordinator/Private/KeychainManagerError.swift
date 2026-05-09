//
//  KeychainManagerError.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/11/26.
//

import Foundation
#if canImport(Security)
import Security
#else
typealias OSStatus = Int32
#endif

enum KeychainManagerError: Error, LocalizedError {
    case securityError(OSStatus)
    case unableToConvertStringToData(String)
    case platformNotSupported

    var errorMessage: String {
        switch self {
        case .securityError(let status):
#if canImport(Security)
            if let cfString = SecCopyErrorMessageString(status, nil) {
                return cfString as String
            } else {
                return "Keychain error with status code: \(status)"
            }
#else
            return "Keychain error with status code: \(status)"
#endif
        case .unableToConvertStringToData(let value):
            return "Unable to convert \(value) to Data"
        case .platformNotSupported:
            return "Keychain is not available on this platform"
        }
    }

    var errorDescription: String? { errorMessage }
}
