import Testing
import Foundation
@testable import VLOAuthFlowCoordinator

// MARK: - Mock Implementations

/// Mock KeychainManager for testing
actor MockKeychainManager: KeychainManager {
    private var storage: [String: Data] = [:]
    var shouldThrowOnSave = false
    var shouldThrowOnLoad = false
    var shouldThrowOnDelete = false
    
    func save(key: String, data: Data) async throws {
        if shouldThrowOnSave {
            throw KeychainManagerError.securityError(errSecIO)
        }
        storage[key] = data
    }
    
    func load(key: String) async throws -> Data? {
        if shouldThrowOnLoad {
            throw KeychainManagerError.securityError(errSecIO)
        }
        return storage[key]
    }
    
    func delete(key: String) async throws {
        if shouldThrowOnDelete {
            throw KeychainManagerError.securityError(errSecIO)
        }
        storage.removeValue(forKey: key)
    }
    
    func clear() {
        storage.removeAll()
    }
    
    func getAllKeys() -> [String] {
        Array(storage.keys)
    }
}
// MARK: - KeychainManager Tests

@Suite("KeychainManager Tests")
struct KeychainManagerTests {
    
    @Test("Save and load data successfully")
    func saveAndLoadData() async throws {
        let keychain = MockKeychainManager()
        let testKey = "test_key"
        let testData = "test_value".data(using: .utf8)!
        
        try await keychain.save(key: testKey, data: testData)
        let loadedData = try await keychain.load(key: testKey)
        
        #expect(loadedData == testData)
    }
    
    @Test("Save and load string successfully")
    func saveAndLoadString() async throws {
        let keychain = MockKeychainManager()
        let testKey = "test_key"
        let testString = "test_value"
        
        try await keychain.save(key: testKey, string: testString)
        let loadedString = try await keychain.loadString(key: testKey)
        
        #expect(loadedString == testString)
    }
    
    @Test("Delete removes data")
    func deleteData() async throws {
        let keychain = MockKeychainManager()
        let testKey = "test_key"
        let testData = "test_value".data(using: .utf8)!
        
        try await keychain.save(key: testKey, data: testData)
        try await keychain.delete(key: testKey)
        let loadedData = try await keychain.load(key: testKey)
        
        #expect(loadedData == nil)
    }
    
    @Test("Load returns nil for non-existent key")
    func loadNonExistentKey() async throws {
        let keychain = MockKeychainManager()
        let loadedData = try await keychain.load(key: "non_existent")
        
        #expect(loadedData == nil)
    }
    
    @Test("Save throws error when configured")
    func saveThrowsError() async throws {
        let keychain = MockKeychainManager()
        await keychain.setShouldThrowOnSave(true)
        
        await #expect(throws: KeychainManagerError.self) {
            try await keychain.save(key: "test", data: Data())
        }
    }
}

// MARK: - OAuthTokenStorageManager Tests

@Suite("OAuthTokenStorageManager Tests")
struct OAuthTokenStorageManagerTests {
    
    @Test("Save and retrieve access token")
    func saveAndRetrieveAccessToken() async throws {
        let keychain = MockKeychainManager()
        let storage = OAuthTokenStorageManager(keychainManager: keychain)
        let token = "test_access_token"
        
        try await storage.save(token, for: .accessToken)
        let retrieved = try await storage.get(tokenType: .accessToken)
        
        #expect(retrieved == token)
    }
    
    @Test("Save and retrieve access token secret")
    func saveAndRetrieveAccessTokenSecret() async throws {
        let keychain = MockKeychainManager()
        let storage = OAuthTokenStorageManager(keychainManager: keychain)
        let secret = "test_secret"
        
        try await storage.save(secret, for: .accessTokenSecret)
        let retrieved = try await storage.get(tokenType: .accessTokenSecret)
        
        #expect(retrieved == secret)
    }
    
    @Test("Save and retrieve request token secret")
    func saveAndRetrieveRequestTokenSecret() async throws {
        let keychain = MockKeychainManager()
        let storage = OAuthTokenStorageManager(keychainManager: keychain)
        let secret = "request_token_secret"
        
        try await storage.save(secret, for: .requestTokenSecret)
        let retrieved = try await storage.get(tokenType: .requestTokenSecret)
        
        #expect(retrieved == secret)
    }
    
    @Test("Delete token removes it from storage")
    func deleteToken() async throws {
        let keychain = MockKeychainManager()
        let storage = OAuthTokenStorageManager(keychainManager: keychain)
        let token = "test_token"
        
        try await storage.save(token, for: .accessToken)
        try await storage.delete(tokenType: .accessToken)
        let retrieved = try await storage.get(tokenType: .accessToken)
        
        #expect(retrieved == nil)
    }
    
    @Test("Save with custom key")
    func saveWithCustomKey() async throws {
        let keychain = MockKeychainManager()
        let storage = OAuthTokenStorageManager(keychainManager: keychain)
        let customKey = "custom_key"
        let token = "custom_token"
        
        try await storage.save(token, for: customKey)
        let retrieved = try await storage.getToken(for: customKey)
        
        #expect(retrieved == token)
    }
}

// MARK: - AccountTokenStorageManager Tests

@Suite("AccountTokenStorageManager Tests")
struct AccountTokenStorageManagerTests {
    
    @Test("Save and retrieve access token for account")
    func saveAndRetrieveAccessToken() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        let token = "access_token_123"
        
        try await accountStorage.saveAccessToken(token)
        let retrieved = try await accountStorage.getAccessToken()
        
        #expect(retrieved == token)
    }
    
    @Test("Save and retrieve access token secret for account")
    func saveAndRetrieveAccessTokenSecret() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        let secret = "token_secret_456"
        
        try await accountStorage.saveAccessTokenSecret(secret)
        let retrieved = try await accountStorage.getAccessTokenSecret()
        
        #expect(retrieved == secret)
    }
    
    @Test("hasValidTokens returns true when both tokens exist")
    func hasValidTokensWithBothTokens() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        
        try await accountStorage.saveAccessToken("token")
        try await accountStorage.saveAccessTokenSecret("secret")
        
        let isValid = try await accountStorage.hasValidTokens()
        #expect(isValid == true)
    }
    
    @Test("hasValidTokens returns false when access token is missing")
    func hasValidTokensWithoutAccessToken() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        
        try await accountStorage.saveAccessTokenSecret("secret")
        
        let isValid = try await accountStorage.hasValidTokens()
        #expect(isValid == false)
    }
    
    @Test("hasValidTokens returns false when secret is missing")
    func hasValidTokensWithoutSecret() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        
        try await accountStorage.saveAccessToken("token")
        
        let isValid = try await accountStorage.hasValidTokens()
        #expect(isValid == false)
    }
    
    @Test("clearTokens removes both access tokens")
    func clearTokens() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        
        try await accountStorage.saveAccessToken("token")
        try await accountStorage.saveAccessTokenSecret("secret")
        try await accountStorage.clearTokens()
        
        let hasTokens = try await accountStorage.hasValidTokens()
        #expect(hasTokens == false)
    }
    
    @Test("Different accounts have isolated storage")
    func isolatedAccountStorage() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        
        let account1 = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user1"
        )
        let account2 = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user2"
        )
        
        try await account1.saveAccessToken("token1")
        try await account2.saveAccessToken("token2")
        
        let token1 = try await account1.getAccessToken()
        let token2 = try await account2.getAccessToken()
        
        #expect(token1 == "token1")
        #expect(token2 == "token2")
        #expect(token1 != token2)
    }
    
    @Test("Request token secret is not account-specific")
    func requestTokenSecretShared() async throws {
        let keychain = MockKeychainManager()
        let tokenStorage = OAuthTokenStorageManager(keychainManager: keychain)
        let accountStorage = AccountTokenStorageManager(
            tokenStorageManager: tokenStorage,
            accountKey: "user123"
        )
        
        let requestSecret = "request_secret_789"
        try await accountStorage.saveRequestTokenSecret(requestSecret)
        let retrieved = try await accountStorage.getRequestTokenSecret()
        
        #expect(retrieved == requestSecret)
    }
}

// MARK: - TokenType Extension Tests

@Suite("TokenType Extension Tests")
struct TokenTypeExtensionTests {
    
    @Test("appendingAccountKey creates correct key format")
    func appendAccountKey() {
        let tokenType = OAuthTokenStorageManager.TokenType.accessToken
        let accountKey = "user123"
        
        let result = tokenType.appendingAccountKey(accountKey)
        
        #expect(result == "oauth_access_token_user123")
    }
    
    @Test("Different token types create different keys")
    func differentTokenTypes() {
        let accountKey = "user123"
        
        let accessTokenKey = OAuthTokenStorageManager.TokenType.accessToken.appendingAccountKey(accountKey)
        let secretKey = OAuthTokenStorageManager.TokenType.accessTokenSecret.appendingAccountKey(accountKey)
        
        #expect(accessTokenKey != secretKey)
        #expect(accessTokenKey == "oauth_access_token_user123")
        #expect(secretKey == "oauth_access_token_secret_user123")
    }
}

// MARK: - KeychainManagerError Tests

@Suite("KeychainManagerError Tests")
struct KeychainManagerErrorTests {
    
    @Test("Error provides localized description")
    func localizedDescription() {
        let error = KeychainManagerError.securityError(errSecItemNotFound)
        let description = error.localizedDescription
        
        #expect(description.isEmpty == false)
    }
    
    @Test("Error message for string conversion failure")
    func stringConversionError() {
        let error = KeychainManagerError.unableToConvertStringToData("test_value")
        let message = error.errorMessage
        
        #expect(message.contains("test_value"))
        #expect(message.contains("Unable to convert"))
    }
    
    @Test("Error conforms to LocalizedError")
    func conformsToLocalizedError() {
        let error: Error = KeychainManagerError.securityError(errSecSuccess)
        let localizedError = error as? LocalizedError
        
        #expect(localizedError != nil)
    }
}

// MARK: - OAuth Token Types Tests

@Suite("OAuth Token Types Tests")
struct OAuthTokenTypesTests {
    
    @Test("OAuthRequestToken is Codable")
    func requestTokenCodable() throws {
        let token = OAuthRequestToken(
            token: "request_token",
            tokenSecret: "request_secret",
            callbackConfirmed: true
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(token)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(OAuthRequestToken.self, from: data)
        
        #expect(decoded.token == token.token)
        #expect(decoded.tokenSecret == token.tokenSecret)
        #expect(decoded.callbackConfirmed == token.callbackConfirmed)
    }
    
    @Test("OAuthVerifier is Codable")
    func verifierCodable() throws {
        let verifier = OAuthVerifier(
            token: "oauth_token",
            verifier: "verification_code"
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(verifier)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(OAuthVerifier.self, from: data)
        
        #expect(decoded.token == verifier.token)
        #expect(decoded.verifier == verifier.verifier)
    }
    
    @Test("OAuthAccessToken is Codable")
    func accessTokenCodable() throws {
        let token = OAuthAccessToken(
            token: "access_token",
            tokenSecret: "access_secret"
        )
        
        let encoder = JSONEncoder()
        let data = try encoder.encode(token)
        
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(OAuthAccessToken.self, from: data)
        
        #expect(decoded.token == token.token)
        #expect(decoded.tokenSecret == token.tokenSecret)
    }
}

// MARK: - Helper Extensions

extension MockKeychainManager {
    func setShouldThrowOnSave(_ value: Bool) async {
        shouldThrowOnSave = value
    }
    
    func setShouldThrowOnLoad(_ value: Bool) async {
        shouldThrowOnLoad = value
    }
    
    func setShouldThrowOnDelete(_ value: Bool) async {
        shouldThrowOnDelete = value
    }
}

