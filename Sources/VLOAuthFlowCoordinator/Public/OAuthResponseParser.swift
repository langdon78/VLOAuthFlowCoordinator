//
//  OAuthResponseParser.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 8/18/25.
//

public protocol OAuthResponseParser {
    func parseOAuthResponse(_ responseString: String) -> [String: String]
}

public extension OAuthResponseParser {
    public func parseOAuthResponse(_ responseString: String) -> [String: String] {
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
