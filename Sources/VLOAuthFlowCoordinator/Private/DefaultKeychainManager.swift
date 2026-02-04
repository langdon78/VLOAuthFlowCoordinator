//
//  DefaultKeychainManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/18/25.
//

import Security
import Foundation
import VLDebugLogger

actor DefaultKeychainManager: KeychainManager {
    
    let logger: VLDebugLogger
    
    init() {
        self.logger = VLDebugLogger(subsystem: "VLOAuthFlowCoordinator", category: .keychain)
    }
    
    func save(key: String, data: Data) async throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        // Delete existing item first
        do {
            if let _ = try await load(key: key) {
                try await delete(key: key)
            }
        } catch {
            logger.log(error, message: "Unable to find key for deletion", category: .keychain)
        }
        
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            // Add new item
            let status = SecItemAdd(query as CFDictionary, nil)
            
            if status == errSecSuccess {
                continuation.resume()
            } else {
                continuation.resume(throwing: KeychainManagerError.securityError(status))
            }
        }
    }
    
    func load(key: String) async throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            var result: AnyObject?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            if status == errSecSuccess || status == errSecItemNotFound {
                continuation.resume(returning: result as? Data)
            } else {
                continuation.resume(throwing: KeychainManagerError.securityError(status))
            }
        }
    }
    
    func delete(key: String) async throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let status = SecItemDelete(query as CFDictionary)
            
            if status == errSecSuccess {
                continuation.resume()
            } else {
                continuation.resume(throwing: KeychainManagerError.securityError(status))
            }
        }
    }
    
}
