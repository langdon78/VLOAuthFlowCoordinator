import SwiftUI
import VLOAuthFlowCoordinator
import VLNetworkingClient
import WebKit
import PlaygroundSupport


let authConfiguration = AuthConfiguration(
    clientKey: "2NVVBip7I5kfl0TwVmGzTphhC98kmXScpZaoz7ET",
    clientSecret: "wXzb8tGqXNbBQ5juA0ZKuFAmSW7RwOw8uSbdE3MvbrI8wjcbGp",
    requestTokenUrl: URL(string: "http://localhost:5001/oauth/request_token")!,
    authorizeUrl: URL(string: "http://localhost:5001/oauth/authorize")!,
    accessTokenUrl: URL(string: "http://localhost:5001/oauth/access_token")!,
    callback: URL(string: "http://localhost:8080")!
)

var url: URL?

let authRequester = AuthRequester(authConfiguration: authConfiguration)

Task {
    do {
        let oauthToken = try await authRequester.requestToken().data
        url = try await authRequester.authorize(requestToken: oauthToken!.token, requestSecret: oauthToken!.tokenSecret).url
        PlaygroundPage.current.setLiveView(ContentView(url: url ?? authConfiguration.authorizeUrl))
    } catch {
        print(error)
    }
}

struct ContentView: View {
    let url: URL
    var body: some View {
        WebView(url: url)
            .frame(width: 1000, height: 1200)
    }
}
