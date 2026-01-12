//
//  AccountTokenStorageManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/4/26.
//

actor AccountTokenStorageManager: AccountTokenStorage {
    private typealias TokenType = OAuthTokenStorageManager.TokenType
    
    var tokenStorageManager: OAuthTokenStorageManager
    let accountKey: String
    
    init(tokenStorageManager: OAuthTokenStorageManager, accountKey: String) {
        self.tokenStorageManager = tokenStorageManager
        self.accountKey = accountKey
    }
    
    // MARK: Saving Tokens
    func saveAccessToken(_ token: String) async throws {
        try await tokenStorageManager.save(token, for: TokenType.accessToken.appendingAccountKey(accountKey))
    }
    
    func saveAccessTokenSecret(_ token: String) async throws {
        try await tokenStorageManager.save(token, for: TokenType.accessTokenSecret.appendingAccountKey(accountKey))
    }
    
    func saveRequestTokenSecret(_ token: String) async throws {
        try await tokenStorageManager.save(token, for: TokenType.requestTokenSecret.rawValue)
    }
    
    // MARK: Retrieve Tokens
    func getAccessToken() async throws -> String? {
        try await tokenStorageManager.getToken(for: TokenType.accessToken.appendingAccountKey(accountKey))
    }

    func getAccessTokenSecret() async throws -> String? {
        try await tokenStorageManager.getToken(for: TokenType.accessTokenSecret.appendingAccountKey(accountKey))
    }
    
    func getRequestTokenSecret() async throws -> String? {
        try await tokenStorageManager.get(tokenType: .requestTokenSecret)
    }
    
    // MARK: Clear Tokens
    func clearTokens() async throws {
        // Only delete tokens if they exist
        if try await getAccessToken() != nil {
            try await tokenStorageManager.deleteToken(for: TokenType.accessToken.appendingAccountKey(accountKey))
        }
        if try await getAccessTokenSecret() != nil {
            try await tokenStorageManager.deleteToken(for: TokenType.accessTokenSecret.appendingAccountKey(accountKey))
        }
    }
    
    // MARK: Token Validation
    func hasValidTokens() async throws -> Bool {
        let hasAccessToken = try await tokenStorageManager.getToken(for: TokenType.accessToken.appendingAccountKey(accountKey)) != nil
        let hasAccessTokenSecret = try await tokenStorageManager.getToken(
            for: TokenType.accessTokenSecret.appendingAccountKey(accountKey)
        ) != nil
        return hasAccessToken && hasAccessTokenSecret
    }
}

extension OAuthTokenStorageManager.TokenType {
    func appendingAccountKey(_ key: String) -> String {
        "\(rawValue)_\(key)"
    }
}
