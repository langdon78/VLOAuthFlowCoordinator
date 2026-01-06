//
//  MultiUserOAuthTokenStorageManager.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/4/26.
//

class MultiUserOAuthTokenStorageManager {
    private typealias TokenType = OAuthTokenStorageManager.TokenType
    static let tempUser: String = "temp"
    
    var tokenStorageManager: OAuthTokenStorageManager
    
    init(tokenStorageManager: OAuthTokenStorageManager) {
        self.tokenStorageManager = tokenStorageManager
    }
    
    
    // MARK: Saving Tokens
    func saveAccessToken(
        _ token: String,
        for user: String = MultiUserOAuthTokenStorageManager.tempUser
    ) -> Bool {
        tokenStorageManager.save(token, for: TokenType.accessToken.appendingUser(user))
    }
    
    func saveAccessTokenSecret(
        _ token: String,
        for user: String = MultiUserOAuthTokenStorageManager.tempUser
    ) -> Bool {
        tokenStorageManager.save(token, for: TokenType.accessTokenSecret.appendingUser(user))
    }
    
    func saveRequestTokenSecret(_ token: String) -> Bool {
        tokenStorageManager.save(token, for: TokenType.requestTokenSecret.rawValue)
    }
    
    func saveAccessTokens(for user: String) throws {
        if let accessToken = getTempAccessToken(),
           let accessTokenSecret = getTempAccessTokenSecret() {
            let didSaveAccessToken = saveAccessToken(accessToken, for: user)
            let didSaveAccessTokenSecret = saveAccessTokenSecret(accessTokenSecret, for: user)
            if !(didSaveAccessToken && didSaveAccessTokenSecret && clearTempTokens()) {
                throw OAuthFlowCooridnatorError.keychainError
            }
        } else {
            throw OAuthFlowCooridnatorError.missingAccessToken
        }
    }
    
    // MARK: Retrieve Tokens
    func getAccessToken(for user: String) -> String? {
        tokenStorageManager.getToken(for: TokenType.accessToken.appendingUser(user))
    }
    
    func getTempAccessToken() -> String? {
        tokenStorageManager.getToken(for: TokenType.accessToken.appendingUser(Self.tempUser))
    }
    
    func getAccessTokenSecret(for user: String) -> String? {
        tokenStorageManager.getToken(for: TokenType.accessTokenSecret.appendingUser(user))
    }
    
    func getTempAccessTokenSecret() -> String? {
        tokenStorageManager.getToken(for: TokenType.accessTokenSecret.appendingUser(Self.tempUser))
    }
    
    func getRequestTokenSecret() -> String? {
        tokenStorageManager.get(tokenType: .requestTokenSecret)
    }
    
    func getAccessToken(for user: String?) -> String? {
        if let user {
            return getAccessToken(for: user)
        } else {
            return getTempAccessToken()
        }
    }
    
    func getAccessTokenSecret(for user: String?) -> String? {
        if let user {
            return getAccessTokenSecret(for: user)
        } else {
            return getTempAccessTokenSecret()
        }
    }
    
    // MARK: Clear Tokens
    func clearTempTokens() -> Bool {
        let accessTokenDeleted = tokenStorageManager.deleteToken(for: TokenType.accessToken.appendingUser(Self.tempUser))
        let accessTokenSecretDeleted = tokenStorageManager.deleteToken(for: TokenType.accessTokenSecret.appendingUser(Self.tempUser))
        return accessTokenDeleted && accessTokenSecretDeleted
    }
    
    func clearAllTokens(for user: String) -> Bool {
        let accessTokenDeleted = tokenStorageManager.deleteToken(for: TokenType.accessToken.appendingUser(user))
        let accessTokenSecretDeleted = tokenStorageManager.deleteToken(for: TokenType.accessTokenSecret.appendingUser(user))
        return accessTokenDeleted && accessTokenSecretDeleted
    }
    
    // MARK: Token Validation
    func hasValidTokens(for user: String) -> Bool {
        let hasAccessToken = tokenStorageManager.getToken(for: TokenType.accessToken.appendingUser(user)) != nil
        let hasAccessTokenSecret = tokenStorageManager.getToken(
            for: TokenType.accessTokenSecret.appendingUser(user)
        ) != nil
        return hasAccessToken && hasAccessTokenSecret
    }
}

extension OAuthTokenStorageManager.TokenType {
    func appendingUser(_ user: String) -> String {
        "\(rawValue)_\(user)"
    }
}
