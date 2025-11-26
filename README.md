# VL (Very Light 🪶) OAuth Flow Coordinator

A Swift package that simplifies OAuth 1.0a authentication flows for iOS and macOS applications. This library handles the complete three-legged OAuth flow, secure token storage, and request signing.

## Features

- Complete OAuth 1.0a three-legged authentication flow
- Secure token storage using Keychain
- ASWebAuthenticationSession integration for user authorization
- Protocol-based architecture for flexible network layer integration
- Automatic request signing for authenticated API calls
- Support for iOS, macOS, tvOS, and watchOS

## Requirements

- iOS 18.0+ / macOS 14.0+ / tvOS 16.0+ / watchOS 6.0+
- Swift 6.2+
- Xcode 16.0+

## Installation

### Swift Package Manager

Add the following to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/langdon78/VLOAuthFlowCoordinator", .upToNextMajor(from: "0.1.0"))
]
```

Or add it through Xcode:
1. File > Add Package Dependencies
2. Enter the repository URL: `https://github.com/langdon78/VLOAuthFlowCoordinator`
3. Select version and add to your target

## Usage

### 1. Configure Your OAuth Provider

First, create a configuration for your OAuth provider:

```swift
import VLOAuthFlowCoordinator

// Define your provider configuration
struct TwitterOAuthConfig: OAuthProviderConfiguration {
    var apiHost = "https://api.twitter.com"
    var requestTokenPath = "/oauth/request_token"
    var accessTokenPath = "/oauth/access_token"
    var authorizationUrl = "https://api.twitter.com/oauth/authorize"
}

// Create client credentials
let credentials = ClientCredentials(
    key: "your-consumer-key",
    secret: "your-consumer-secret"
)

// Create auth configuration
let authConfig = AuthConfiguration(
    clientCredentials: credentials,
    provider: TwitterOAuthConfig(),
    callback: URL(string: "myapp://oauth-callback")!
)
```

### 2. Implement NetworkProvider

You must provide a `NetworkProvider` implementation to handle network requests. This allows you to use your preferred networking library:

```swift
import Foundation

class MyNetworkProvider: NetworkProvider {
    func getRequestToken(from request: URLRequest) async throws -> OAuthRequestToken? {
        let (data, _) = try await URLSession.shared.data(for: request)

        guard let responseString = String(data: data, encoding: .utf8) else {
            return nil
        }

        let params = parseOAuthResponse(responseString)

        guard let token = params["oauth_token"],
              let tokenSecret = params["oauth_token_secret"],
              let callbackConfirmed = params["oauth_callback_confirmed"] else {
            return nil
        }

        return OAuthRequestToken(
            token: token,
            tokenSecret: tokenSecret,
            callbackConfirmed: callbackConfirmed == "true"
        )
    }

    func getAccessToken(from request: URLRequest) async throws -> OAuthAccessToken? {
        let (data, _) = try await URLSession.shared.data(for: request)

        guard let responseString = String(data: data, encoding: .utf8) else {
            return nil
        }

        let params = parseOAuthResponse(responseString)

        guard let token = params["oauth_token"],
              let tokenSecret = params["oauth_token_secret"] else {
            return nil
        }

        return OAuthAccessToken(token: token, tokenSecret: tokenSecret)
    }

    func decodeVerifierResponse(from authorizationResponseQuery: String) throws -> OAuthVerifier? {
        let params = parseOAuthResponse(authorizationResponseQuery)

        guard let token = params["oauth_token"],
              let verifier = params["oauth_verifier"] else {
            return nil
        }

        return OAuthVerifier(token: token, verifier: verifier)
    }

    private func parseOAuthResponse(_ responseString: String) -> [String: String] {
        let pairs = responseString.components(separatedBy: "&")
        var result: [String: String] = [:]

        for pair in pairs {
            let keyValue = pair.components(separatedBy: "=")
            if keyValue.count == 2 {
                let key = keyValue[0]
                let value = keyValue[1].removingPercentEncoding ?? keyValue[1]
                result[key] = value
            }
        }

        return result
    }
}
```

### 3. Start the OAuth Flow

Initialize the coordinator and start the authentication flow:

```swift
import VLOAuthFlowCoordinator

class AuthenticationManager {
    private var coordinator: OAuthFlowCoordinator?

    func authenticate() async throws {
        // Create the coordinator
        coordinator = OAuthFlowCoordinator(
            authConfiguration: authConfig,
            networkProvider: MyNetworkProvider(),
            onSuccessfulAuthentication: {
                print("Authentication successful!")
                // Perform post-authentication tasks
            }
        )

        // Start the OAuth flow
        try await coordinator?.startOAuthFlow()
    }

    func checkAuthenticationStatus() -> Bool {
        return coordinator?.hasValidTokens() ?? false
    }

    func signOut() {
        coordinator?.clearToken()
    }
}
```

### 4. Sign API Requests

After authentication, use the coordinator to sign your API requests:

```swift
// Create your API request
var request = URLRequest(url: URL(string: "https://api.twitter.com/1.1/account/verify_credentials.json")!)
request.httpMethod = "GET"

// Sign the request with OAuth credentials
let signedRequest = try await coordinator.getSignedRequest(from: request)

// Use the signed request
let (data, response) = try await URLSession.shared.data(for: signedRequest)
```

### 5. Complete Example with SwiftUI

```swift
import SwiftUI
import VLOAuthFlowCoordinator

@MainActor
class AuthViewModel: ObservableObject {
    @Published var isAuthenticated = false
    @Published var errorMessage: String?

    private var coordinator: OAuthFlowCoordinator?

    init() {
        setupCoordinator()
        isAuthenticated = coordinator?.hasValidTokens() ?? false
    }

    private func setupCoordinator() {
        let credentials = ClientCredentials(
            key: "your-key",
            secret: "your-secret"
        )

        let config = AuthConfiguration(
            clientCredentials: credentials,
            provider: TwitterOAuthConfig(),
            callback: URL(string: "myapp://oauth-callback")!
        )

        coordinator = OAuthFlowCoordinator(
            authConfiguration: config,
            networkProvider: MyNetworkProvider(),
            onSuccessfulAuthentication: { [weak self] in
                await MainActor.run {
                    self?.isAuthenticated = true
                }
            }
        )
    }

    func signIn() async {
        do {
            try await coordinator?.startOAuthFlow()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func signOut() {
        coordinator?.clearToken()
        isAuthenticated = false
    }
}

struct ContentView: View {
    @StateObject private var viewModel = AuthViewModel()

    var body: some View {
        VStack(spacing: 20) {
            if viewModel.isAuthenticated {
                Text("You are authenticated!")
                Button("Sign Out") {
                    viewModel.signOut()
                }
            } else {
                Button("Sign In with OAuth") {
                    Task {
                        await viewModel.signIn()
                    }
                }
            }

            if let error = viewModel.errorMessage {
                Text(error)
                    .foregroundColor(.red)
            }
        }
        .padding()
    }
}
```

## Configuration

### URL Callback Setup

Add your callback URL scheme to your app's `Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

### Provider Configurations

You can create reusable provider configurations for common OAuth services:

```swift
// Twitter
struct TwitterConfig: OAuthProviderConfiguration {
    var apiHost = "https://api.twitter.com"
    var requestTokenPath = "/oauth/request_token"
    var accessTokenPath = "/oauth/access_token"
    var authorizationUrl = "https://api.twitter.com/oauth/authorize"
}

// Tumblr
struct TumblrConfig: OAuthProviderConfiguration {
    var apiHost = "https://www.tumblr.com"
    var requestTokenPath = "/oauth/request_token"
    var accessTokenPath = "/oauth/access_token"
    var authorizationUrl = "https://www.tumblr.com/oauth/authorize"
}
```

## Architecture

The library follows a protocol-based architecture with clear separation of concerns:

- **OAuthFlowCoordinator**: Main coordinator that orchestrates the OAuth flow
- **NetworkProvider**: Protocol for network operations (you implement this)
- **AuthConfiguration**: Contains OAuth provider endpoints and credentials
- **OAuthTokenStorageManager**: Handles secure token storage in Keychain
- **VLOAuthProvider**: Dependency for OAuth signature generation

## Token Storage

Tokens are automatically stored securely in the iOS/macOS Keychain. The library manages:

- Access tokens
- Access token secrets
- Request token secrets (temporary, during flow)

You can check token status and clear tokens:

```swift
// Check if valid tokens exist
let hasTokens = coordinator.hasValidTokens()

// Clear all stored tokens
coordinator.clearToken()
```

## Error Handling

The library throws `OAuthFlowCoordinatorError` for various error conditions:

- `.missingRequestToken`: Failed to obtain request token
- `.missingAccessToken`: Failed to obtain access token
- `.malformedRequest`: Invalid request construction
- `.invalidCallbackUrl`: Callback URL validation failed
- `.unknownConfiguration`: Configuration error

```swift
do {
    try await coordinator.startOAuthFlow()
} catch OAuthFlowCoordinatorError.missingRequestToken {
    print("Failed to get request token")
} catch OAuthFlowCoordinatorError.invalidCallbackUrl {
    print("Invalid callback URL")
} catch {
    print("Authentication error: \(error)")
}
```

## Dependencies

- [VLOAuthProvider](https://github.com/langdon78/VLOAuthProvider): OAuth 1.0a signature generation

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
