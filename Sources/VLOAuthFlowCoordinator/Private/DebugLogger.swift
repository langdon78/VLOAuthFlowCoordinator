//
//  DebugLogger.swift
//  VLOAuthFlowCoordinator
//
//  Created by James Langdon on 1/11/26.
//

import Foundation
import os.log

/// A debug logger for VLOAuthFlowCoordinator that provides consistent logging across the framework.
final class DebugLogger: @unchecked Sendable {
    
    // MARK: - Singleton
    
    static let shared = DebugLogger()
    
    // MARK: - Properties
    
    private let logger: Logger
    private let subsystem = "com.VLOAuthFlowCoordinator"
    
    /// Controls whether debug logging is enabled. Set to false in production builds.
    var isEnabled: Bool = false
    
    // Skip OS logging and print directly to debug console
    var consoleOnly: Bool = true
    
    // MARK: - Log Categories
    
    enum Category: String {
        case oauth = "OAuth"
        case keychain = "Keychain"
        case network = "Network"
        case general = "General"
        case error = "Error"
    }
    
    // MARK: - Initialization
    
    private init() {
        self.logger = Logger(subsystem: subsystem, category: "VLOAuthFlowCoordinator")
        
        #if DEBUG
        isEnabled = true
        #endif
    }
    
    // MARK: - Public Logging Methods
    
    /// Log a debug message
    /// - Parameters:
    ///   - message: The message to log
    ///   - category: Optional category for filtering logs
    func debug(_ message: String, category: Category = .general) {
        guard isEnabled else { return }
        let logMessage = "[\(category.rawValue)] 🔎 \(message)"
        
        if consoleOnly {
            print("DEBUG \(logMessage)")
        } else {
            logger.debug("\(logMessage)")
        }
    }
    
    /// Log an info message
    /// - Parameters:
    ///   - message: The message to log
    ///   - category: Optional category for filtering logs
    func info(_ message: String, category: Category = .general) {
        guard isEnabled else { return }
        let logMessage = "[\(category.rawValue)] 📣 \(message)"
        
        if consoleOnly {
            print("DEBUG \(logMessage)")
        } else {
            logger.info("\(logMessage)")
        }
    }
    
    /// Log a warning message
    /// - Parameters:
    ///   - message: The message to log
    ///   - category: Optional category for filtering logs
    func warning(_ message: String, category: Category = .general) {
        guard isEnabled else { return }
        let logMessage = "[\(category.rawValue)] ⚠️ \(message)"
        
        if consoleOnly {
            print("DEBUG \(logMessage)")
        } else {
            logger.warning("\(logMessage)")
        }
    }
    
    /// Log an error message
    /// - Parameters:
    ///   - message: The message to log
    ///   - error: Optional error object to include
    ///   - category: Optional category for filtering logs
    func error(_ message: String, error: Error? = nil, category: Category = .error) {
        guard isEnabled else { return }
        var logMessage = ""
        if let error = error {
            logMessage = "[\(category.rawValue)] ❌ \(message) - Error: \(String(describing: error.localizedDescription))"
        } else {
            logMessage = "[\(category.rawValue)] ❌ \(message)"
        }
        
        if consoleOnly {
            print("DEBUG \(logMessage)")
        } else {
            logger.error("\(logMessage)")
        }
    }
    
    /// Log a critical error
    /// - Parameters:
    ///   - message: The message to log
    ///   - error: Optional error object to include
    ///   - category: Optional category for filtering logs
    func critical(_ message: String, error: Error? = nil, category: Category = .error) {
        guard isEnabled else { return }
        var logMessage = ""
        if let error = error {
            logMessage = "[\(category.rawValue)] 🔴 \(message) - Error: \(error.localizedDescription)"
        } else {
            logMessage = "[\(category.rawValue)] 🔴 \(message)"
        }
        
        if consoleOnly {
            print("DEBUG \(logMessage)")
        } else {
            logger.critical("\(logMessage)")
        }
    }
    
    // MARK: - Convenience Methods for Specific Categories
    
    /// Log an OAuth-related message
    func logOAuth(_ message: String, level: LogLevel = .debug) {
        log(message, category: .oauth, level: level)
    }
    
    /// Log a Keychain-related message
    func logKeychain(_ message: String, level: LogLevel = .debug) {
        log(message, category: .keychain, level: level)
    }
    
    /// Log a Network-related message
    func logNetwork(_ message: String, level: LogLevel = .debug) {
        log(message, category: .network, level: level)
    }
    
    // MARK: - Private Helpers
    
    private func log(_ message: String, category: Category, level: LogLevel) {
        switch level {
        case .debug:
            debug(message, category: category)
        case .info:
            info(message, category: category)
        case .warning:
            warning(message, category: category)
        case .error:
            error(message, category: category)
        case .critical:
            critical(message, category: category)
        }
    }
}

// MARK: - Log Level

extension DebugLogger {
    enum LogLevel {
        case debug
        case info
        case warning
        case error
        case critical
    }
}

// MARK: - Global Convenience Functions

/// Global debug log function
func logDebug(_ message: String) {
    DebugLogger.shared.debug(message)
}

/// Global info log function
func logInfo(_ message: String) {
    DebugLogger.shared.info(message)
}

/// Global warning log function
func logWarning(_ message: String) {
    DebugLogger.shared.warning(message)
}

/// Global error log function
func logError(_ message: String, error: Error? = nil) {
    DebugLogger.shared.error(message, error: error)
}
