//
//  OAuthTokenStorageManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 11/23/25.
//

actor OAuthTokenStorageManager: OAuthTokenStorage {
    enum TokenType: String {
        case accessToken = "oauth_access_token"
        case accessTokenSecret = "oauth_access_token_secret"
        case requestTokenSecret = "oauth_request_token_secret"
    }
    
    let keychainManager: KeychainManager
    
    init(keychainManager: KeychainManager) {
        self.keychainManager = keychainManager
    }
    
    // MARK: - Save Tokens
    func save(_ token: String, for tokenType: TokenType) async throws {
        try await save(token, for: tokenType.rawValue)
    }
    
    func save(_ token: String, for key: String) async throws {
        try await keychainManager.save(key: key, string: token)
    }
    
    // MARK: - Get Tokens
    func get(tokenType: TokenType) async throws -> String? {
        try await getToken(for: tokenType.rawValue)
    }
    
    func getToken(for key: String) async throws -> String? {
        try await keychainManager.loadString(key: key)
    }
    
    // MARK: - Delete Tokens
    func delete(tokenType: TokenType) async throws {
        try await deleteToken(for: tokenType.rawValue)
    }
    
    func deleteToken(for key: String) async throws {
        try await keychainManager.delete(key: key)
    }
}
