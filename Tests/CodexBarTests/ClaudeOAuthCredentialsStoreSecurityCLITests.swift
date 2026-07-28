import Foundation
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct ClaudeOAuthCredentialsStoreSecurityCLITests {
    private func makeCredentialsData(accessToken: String, expiresAt: Date, refreshToken: String? = nil) -> Data {
        let millis = Int(expiresAt.timeIntervalSince1970 * 1000)
        let refreshField: String = {
            guard let refreshToken else { return "" }
            return ",\n            \"refreshToken\": \"\(refreshToken)\""
        }()
        let json = """
        {
          "claudeAiOauth": {
            "accessToken": "\(accessToken)",
            "expiresAt": \(millis),
            "scopes": ["user:profile"]\(refreshField)
          }
        }
        """
        return Data(json.utf8)
    }

    @Test
    func `experimental reader cannot seed a non interactive cache miss`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")

                ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let securityData = self.makeCredentialsData(
                        accessToken: "security-token",
                        expiresAt: Date(timeIntervalSinceNow: 3600),
                        refreshToken: "security-refresh")

                    let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                        try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                            .securityCLIExperimental,
                            operation: {
                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                    .onlyOnUserAction,
                                    operation: {
                                        try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                            try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                                .data(securityData))
                                            {
                                                try ClaudeOAuthCredentialsStore.load(
                                                    environment: [:],
                                                    allowKeychainPrompt: false)
                                            }
                                        }
                                    })
                            })
                    }
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(String(describing: error))")
                        return
                    }
                }
            }
        }
    }

    @Test
    func `background cache miss skips the experimental reader`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")

                ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let securityData = self.makeCredentialsData(
                        accessToken: "security-token-background",
                        expiresAt: Date(timeIntervalSinceNow: 3600),
                        refreshToken: "security-refresh-background")
                    final class ReadCounter: @unchecked Sendable {
                        var hits = 0
                    }
                    let securityReadCalls = ReadCounter()

                    let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                        try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                            .securityCLIExperimental,
                            operation: {
                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                    .onlyOnUserAction,
                                    operation: {
                                        try ProviderInteractionContext.$current.withValue(.background) {
                                            try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                                .dynamic { _ in
                                                    securityReadCalls.hits += 1
                                                    return securityData
                                                }) {
                                                    try ClaudeOAuthCredentialsStore.load(
                                                        environment: [:],
                                                        allowKeychainPrompt: false)
                                                }
                                        }
                                    })
                            })
                    }
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(String(describing: error))")
                        return
                    }
                    #expect(securityReadCalls.hits == 0)
                }
            }
        }
    }
}

extension ClaudeOAuthCredentialsStoreSecurityCLITests {
    @Test
    func `cache miss ignores ambient fallback when experimental reader throws`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")

                ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let fallbackData = self.makeCredentialsData(
                        accessToken: "fallback-token",
                        expiresAt: Date(timeIntervalSinceNow: 3600),
                        refreshToken: "fallback-refresh")

                    let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                        try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                            .securityCLIExperimental,
                            operation: {
                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                    .onlyOnUserAction,
                                    operation: {
                                        try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                            try ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                                data: fallbackData,
                                                fingerprint: nil)
                                            {
                                                try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                                    .timedOut)
                                                {
                                                    try ClaudeOAuthCredentialsStore.load(
                                                        environment: [:],
                                                        allowKeychainPrompt: false)
                                                }
                                            }
                                        }
                                    })
                            })
                    }
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(String(describing: error))")
                        return
                    }
                }
            }
        }
    }

    @Test
    func `cache miss ignores ambient fallback when experimental reader output is malformed`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")

                ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let fallbackData = self.makeCredentialsData(
                        accessToken: "fallback-token",
                        expiresAt: Date(timeIntervalSinceNow: 3600))

                    let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                        try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                            .securityCLIExperimental,
                            operation: {
                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                    .onlyOnUserAction,
                                    operation: {
                                        try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                            try ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                                data: fallbackData,
                                                fingerprint: nil)
                                            {
                                                try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                                    .data(Data("not-json".utf8)))
                                                {
                                                    try ClaudeOAuthCredentialsStore.load(
                                                        environment: [:],
                                                        allowKeychainPrompt: false)
                                                }
                                            }
                                        }
                                    })
                            })
                    }
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(String(describing: error))")
                        return
                    }
                }
            }
        }
    }

    @Test
    func `experimental reader load from claude keychain uses security CLI`() throws {
        let securityData = self.makeCredentialsData(
            accessToken: "security-direct",
            expiresAt: Date(timeIntervalSinceNow: 3600),
            refreshToken: "security-refresh")
        let fingerprintStore = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprintStore()
        let sentinelFingerprint = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint(
            modifiedAt: 200,
            createdAt: 199,
            persistentRefHash: "sentinel")

        let loaded = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
            .securityCLIExperimental,
            operation: {
                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                    .always,
                    operation: {
                        try ProviderInteractionContext.$current.withValue(.userInitiated) {
                            try ClaudeOAuthCredentialsStore.withClaudeKeychainFingerprintStoreOverrideForTesting(
                                fingerprintStore)
                            {
                                try ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                    data: nil,
                                    fingerprint: sentinelFingerprint)
                                {
                                    try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                        .data(securityData))
                                    {
                                        try ClaudeOAuthCredentialsStore.loadFromClaudeKeychain()
                                    }
                                }
                            }
                        }
                    })
            })

        let creds = try ClaudeOAuthCredentials.parse(data: loaded)
        #expect(creds.accessToken == "security-direct")
        #expect(creds.refreshToken == "security-refresh")
        #expect(fingerprintStore.fingerprint == nil)
    }

    @Test
    func `experimental reader has claude keychain credentials without prompt uses security CLI`() {
        let securityData = self.makeCredentialsData(
            accessToken: "security-available",
            expiresAt: Date(timeIntervalSinceNow: 3600))

        let hasCredentials = ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
            .securityCLIExperimental,
            operation: {
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                    .always,
                    operation: {
                        ProviderInteractionContext.$current.withValue(.userInitiated) {
                            ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                .data(securityData))
                            {
                                ClaudeOAuthCredentialsStore.hasClaudeKeychainCredentialsWithoutPrompt()
                            }
                        }
                    })
            })

        #expect(hasCredentials == true)
    }

    @Test
    func `experimental reader has claude keychain credentials without prompt falls back when security CLI fails`() {
        let fallbackData = self.makeCredentialsData(
            accessToken: "fallback-available",
            expiresAt: Date(timeIntervalSinceNow: 3600))

        let hasCredentials = ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
            .securityCLIExperimental,
            operation: {
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                    .always,
                    operation: {
                        ProviderInteractionContext.$current.withValue(.userInitiated) {
                            ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                data: fallbackData,
                                fingerprint: nil)
                            {
                                ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                    .nonZeroExit)
                                {
                                    ClaudeOAuthCredentialsStore.hasClaudeKeychainCredentialsWithoutPrompt()
                                }
                            }
                        }
                    })
            })

        #expect(hasCredentials == true)
    }

    @Test
    func `experimental reader ignores prompt policy and cooldown for background silent check`() {
        let securityData = self.makeCredentialsData(
            accessToken: "security-background",
            expiresAt: Date(timeIntervalSinceNow: 3600))

        let hasCredentials = KeychainAccessGate.withTaskOverrideForTesting(false) {
            ClaudeOAuthKeychainAccessGate.withShouldAllowPromptOverrideForTesting(false) {
                ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                    .securityCLIExperimental,
                    operation: {
                        ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                            .never,
                            operation: {
                                ProviderInteractionContext.$current.withValue(.background) {
                                    ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                        .data(securityData))
                                    {
                                        ClaudeOAuthCredentialsStore.hasClaudeKeychainCredentialsWithoutPrompt()
                                    }
                                }
                            })
                    })
            }
        }

        #expect(hasCredentials == false)
    }

    @Test
    func `experimental reader load from claude keychain fallback blocked when stored mode never`() throws {
        var threwNotFound = false
        do {
            _ = try KeychainAccessGate.withTaskOverrideForTesting(false) {
                try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                    .securityCLIExperimental,
                    operation: {
                        try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                            .never,
                            operation: {
                                try ProviderInteractionContext.$current.withValue(.background) {
                                    try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                        .nonZeroExit)
                                    {
                                        try ClaudeOAuthCredentialsStore.loadFromClaudeKeychain()
                                    }
                                }
                            })
                    })
            }
        } catch let error as ClaudeOAuthCredentialsError {
            if case .notFound = error {
                threwNotFound = true
            }
        }

        #expect(threwNotFound == true)
    }

    @Test
    func `experimental reader security CLI read pins preferred account when available`() throws {
        let securityData = self.makeCredentialsData(
            accessToken: "security-account-pinned",
            expiresAt: Date(timeIntervalSinceNow: 3600))
        final class AccountBox: @unchecked Sendable {
            var value: String?
        }
        let pinnedAccount = AccountBox()

        let loaded = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
            .securityCLIExperimental,
            operation: {
                try ClaudeOAuthCredentialsStore.withSecurityCLIReadAccountOverrideForTesting("new-account") {
                    try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                        .always,
                        operation: {
                            try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                    .dynamic { request in
                                        pinnedAccount.value = request.account
                                        return securityData
                                    }) {
                                        try ClaudeOAuthCredentialsStore.loadFromClaudeKeychain()
                                    }
                            }
                        })
                }
            })

        let creds = try ClaudeOAuthCredentials.parse(data: loaded)
        #expect(pinnedAccount.value == "new-account")
        #expect(creds.accessToken == "security-account-pinned")
    }

    @Test
    func `experimental reader security CLI read does not pin account in background`() throws {
        let securityData = self.makeCredentialsData(
            accessToken: "security-account-not-pinned",
            expiresAt: Date(timeIntervalSinceNow: 3600))
        final class AccountBox: @unchecked Sendable {
            var value: String?
        }
        let pinnedAccount = AccountBox()

        let loaded = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
            .securityCLIExperimental,
            operation: {
                try ClaudeOAuthCredentialsStore.withSecurityCLIReadAccountOverrideForTesting("new-account") {
                    try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                        .always,
                        operation: {
                            try ProviderInteractionContext.$current.withValue(.background) {
                                try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                    .dynamic { request in
                                        pinnedAccount.value = request.account
                                        return securityData
                                    }) {
                                        try ClaudeOAuthCredentialsStore.loadFromClaudeKeychain()
                                    }
                            }
                        })
                }
            })

        let creds = try ClaudeOAuthCredentials.parse(data: loaded)
        #expect(pinnedAccount.value == nil)
        #expect(creds.accessToken == "security-account-not-pinned")
    }

    @Test
    func `cache miss skips the experimental reader regardless of preflight`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                try ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                    try ClaudeOAuthCredentialsStore.withIsolatedCredentialsFileTrackingForTesting {
                        ClaudeOAuthCredentialsStore.invalidateCache()
                        ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                        defer {
                            ClaudeOAuthCredentialsStore.invalidateCache()
                            ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                        }

                        let tempDir = FileManager.default.temporaryDirectory
                            .appendingPathComponent(UUID().uuidString, isDirectory: true)
                        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                        let fileURL = tempDir.appendingPathComponent("credentials.json")
                        ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                            let securityData = self.makeCredentialsData(
                                accessToken: "security-sync",
                                expiresAt: Date(timeIntervalSinceNow: 3600))
                            final class ReadCounter: @unchecked Sendable {
                                var hits = 0
                            }
                            let securityReadCalls = ReadCounter()

                            func loadWithPreflight(
                                _ outcome: KeychainAccessPreflight.Outcome) -> ClaudeOAuthCredentialsError?
                            {
                                let preflightOverride: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in
                                    outcome
                                }
                                return #expect(throws: ClaudeOAuthCredentialsError.self) {
                                    try KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(
                                        preflightOverride,
                                        operation: {
                                            try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                                                .securityCLIExperimental)
                                            {
                                                try ClaudeOAuthKeychainPromptPreference
                                                    .withTaskOverrideForTesting(.always) {
                                                        try ProviderInteractionContext.$current.withValue(.background) {
                                                            try ClaudeOAuthCredentialsStore
                                                                .withSecurityCLIReadOverrideForTesting(
                                                                    .dynamic { _ in
                                                                        securityReadCalls.hits += 1
                                                                        return securityData
                                                                    }) {
                                                                        try ClaudeOAuthCredentialsStore.load(
                                                                            environment: [:],
                                                                            allowKeychainPrompt: false,
                                                                            respectKeychainPromptCooldown: true)
                                                                }
                                                        }
                                                    }
                                            }
                                        })
                                }
                            }

                            guard case .notFound? = loadWithPreflight(.allowed),
                                  case .notFound? = loadWithPreflight(.interactionRequired)
                            else {
                                Issue.record("Expected both ambient loads to fail closed")
                                return
                            }
                            #expect(securityReadCalls.hits == 0)
                        }
                    }
                }
            }
        }
    }

    @Test
    func `cache miss skips the experimental reader regardless of interaction`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                try ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                    try ClaudeOAuthCredentialsStore.withIsolatedCredentialsFileTrackingForTesting {
                        ClaudeOAuthCredentialsStore.invalidateCache()
                        ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                        defer {
                            ClaudeOAuthCredentialsStore.invalidateCache()
                            ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                        }

                        let tempDir = FileManager.default.temporaryDirectory
                            .appendingPathComponent(UUID().uuidString, isDirectory: true)
                        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                        let fileURL = tempDir.appendingPathComponent("credentials.json")
                        ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                            let securityData = self.makeCredentialsData(
                                accessToken: "security-sync-only-on-user-action",
                                expiresAt: Date(timeIntervalSinceNow: 3600))
                            final class ReadCounter: @unchecked Sendable {
                                var hits = 0
                            }
                            let securityReadCalls = ReadCounter()
                            let preflightOverride: (String, String?) -> KeychainAccessPreflight.Outcome = { _, _ in
                                .allowed
                            }

                            func load(_ interaction: ProviderInteraction) -> ClaudeOAuthCredentialsError? {
                                #expect(throws: ClaudeOAuthCredentialsError.self) {
                                    try KeychainAccessPreflight.withCheckGenericPasswordOverrideForTesting(
                                        preflightOverride,
                                        operation: {
                                            try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                                                .securityCLIExperimental)
                                            {
                                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(
                                                    .onlyOnUserAction)
                                                {
                                                    try ProviderInteractionContext.$current.withValue(interaction) {
                                                        try ClaudeOAuthCredentialsStore
                                                            .withSecurityCLIReadOverrideForTesting(
                                                                .dynamic { _ in
                                                                    securityReadCalls.hits += 1
                                                                    return securityData
                                                                }) {
                                                                    try ClaudeOAuthCredentialsStore.load(
                                                                        environment: [:],
                                                                        allowKeychainPrompt: false,
                                                                        respectKeychainPromptCooldown: true)
                                                            }
                                                    }
                                                }
                                            }
                                        })
                                }
                            }

                            guard case .notFound? = load(.userInitiated),
                                  case .notFound? = load(.background)
                            else {
                                Issue.record("Expected both ambient loads to fail closed")
                                return
                            }
                            #expect(securityReadCalls.hits == 0)
                        }
                    }
                }
            }
        }
    }

    @Test
    func `experimental reader sync skips fingerprint probe after security CLI read`() {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        KeychainCacheStore.withServiceOverrideForTesting(service) {
            KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    defer { ClaudeOAuthCredentialsStore.invalidateCache() }

                    let securityData = self.makeCredentialsData(
                        accessToken: "security-sync-no-fingerprint-probe",
                        expiresAt: Date(timeIntervalSinceNow: 3600))
                    let fingerprintStore = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprintStore()
                    let sentinelFingerprint = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint(
                        modifiedAt: 123,
                        createdAt: 122,
                        persistentRefHash: "sentinel")

                    let synced = ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                        .securityCLIExperimental,
                        operation: {
                            ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.always) {
                                ProviderInteractionContext.$current.withValue(.background) {
                                    ClaudeOAuthCredentialsStore.withClaudeKeychainFingerprintStoreOverrideForTesting(
                                        fingerprintStore)
                                    {
                                        ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                            data: nil,
                                            fingerprint: sentinelFingerprint)
                                        {
                                            ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                                .data(securityData))
                                            {
                                                ClaudeOAuthCredentialsStore.syncFromClaudeKeychainAfterDelegatedRefresh(
                                                    now: Date())
                                            }
                                        }
                                    }
                                }
                            }
                        })

                    #expect(synced == true)
                    #expect(fingerprintStore.fingerprint == nil)
                }
            }
        }
    }

    @Test
    func `experimental reader cannot repair an ordinary cache miss`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                try ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                    try ClaudeOAuthCredentialsStore.withIsolatedCredentialsFileTrackingForTesting {
                        let tempDir = FileManager.default.temporaryDirectory
                            .appendingPathComponent(UUID().uuidString, isDirectory: true)
                        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                        let fileURL = tempDir.appendingPathComponent("credentials.json")
                        ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                            let securityData = self.makeCredentialsData(
                                accessToken: "security-repair-no-fingerprint-probe",
                                expiresAt: Date(timeIntervalSinceNow: 3600))
                            let fingerprintStore = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprintStore()
                            let sentinelFingerprint = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint(
                                modifiedAt: 456,
                                createdAt: 455,
                                persistentRefHash: "sentinel")

                            let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                                try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                                    .securityCLIExperimental,
                                    operation: {
                                        try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.always) {
                                            try ProviderInteractionContext.$current.withValue(.background) {
                                                try ClaudeOAuthCredentialsStore
                                                    .withClaudeKeychainFingerprintStoreOverrideForTesting(
                                                        fingerprintStore)
                                                    {
                                                        try ClaudeOAuthCredentialsStore
                                                            .withClaudeKeychainOverridesForTesting(
                                                                data: nil,
                                                                fingerprint: sentinelFingerprint)
                                                            {
                                                                try ClaudeOAuthCredentialsStore
                                                                    .withSecurityCLIReadOverrideForTesting(
                                                                        .data(securityData))
                                                                    {
                                                                        try ClaudeOAuthCredentialsStore.loadRecord(
                                                                            environment: [:],
                                                                            allowKeychainPrompt: false,
                                                                            respectKeychainPromptCooldown: true)
                                                                    }
                                                            }
                                                    }
                                            }
                                        }
                                    })
                            }
                            guard case .notFound = error else {
                                Issue.record("Expected .notFound, got \(String(describing: error))")
                                return
                            }
                            #expect(fingerprintStore.fingerprint == nil)
                        }
                    }
                }
            }
        }
    }

    @Test
    func `experimental reader load with prompt skips fingerprint probe after security CLI success`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(false) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                try ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                    try ClaudeOAuthCredentialsStore.withIsolatedCredentialsFileTrackingForTesting {
                        let tempDir = FileManager.default.temporaryDirectory
                            .appendingPathComponent(UUID().uuidString, isDirectory: true)
                        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                        let fileURL = tempDir.appendingPathComponent("credentials.json")
                        try ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                            let securityData = self.makeCredentialsData(
                                accessToken: "security-load-with-prompt",
                                expiresAt: Date(timeIntervalSinceNow: 3600))
                            let fingerprintStore = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprintStore()
                            let sentinelFingerprint = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint(
                                modifiedAt: 321,
                                createdAt: 320,
                                persistentRefHash: "sentinel")

                            let creds = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                                .securityCLIExperimental,
                                operation: {
                                    try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.always) {
                                        try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                            try ClaudeOAuthCredentialsStore
                                                .withClaudeKeychainFingerprintStoreOverrideForTesting(
                                                    fingerprintStore)
                                                {
                                                    try ClaudeOAuthCredentialsStore
                                                        .withClaudeKeychainOverridesForTesting(
                                                            data: nil,
                                                            fingerprint: sentinelFingerprint)
                                                        {
                                                            try ClaudeOAuthCredentialsStore
                                                                .withSecurityCLIReadOverrideForTesting(
                                                                    .data(securityData))
                                                                {
                                                                    try ClaudeOAuthCredentialsStore.load(
                                                                        environment: [:],
                                                                        allowKeychainPrompt: true,
                                                                        respectKeychainPromptCooldown: false)
                                                                }
                                                        }
                                                }
                                        }
                                    }
                                })

                            #expect(creds.accessToken == "security-load-with-prompt")
                            #expect(fingerprintStore.fingerprint == nil)
                        }
                    }
                }
            }
        }
    }

    @Test
    func `experimental reader load with prompt does not read when global keychain disabled`() throws {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        try KeychainCacheStore.withServiceOverrideForTesting(service) {
            try KeychainAccessGate.withTaskOverrideForTesting(true) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                ClaudeOAuthCredentialsStore.invalidateCache()
                ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                defer {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                    ClaudeOAuthCredentialsStore._resetCredentialsFileTrackingForTesting()
                }

                let tempDir = FileManager.default.temporaryDirectory
                    .appendingPathComponent(UUID().uuidString, isDirectory: true)
                try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
                let fileURL = tempDir.appendingPathComponent("credentials.json")
                try ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
                    let securityData = self.makeCredentialsData(
                        accessToken: "security-should-not-read",
                        expiresAt: Date(timeIntervalSinceNow: 3600))
                    var threwNotFound = false
                    final class ReadCounter: @unchecked Sendable {
                        var hits = 0
                    }
                    let securityReadCalls = ReadCounter()

                    do {
                        _ = try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                            .securityCLIExperimental,
                            operation: {
                                try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.always) {
                                    try ProviderInteractionContext.$current.withValue(.userInitiated) {
                                        try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                            .dynamic { _ in
                                                securityReadCalls.hits += 1
                                                return securityData
                                            }) {
                                                try ClaudeOAuthCredentialsStore.load(
                                                    environment: [:],
                                                    allowKeychainPrompt: true,
                                                    respectKeychainPromptCooldown: false)
                                            }
                                    }
                                }
                            })
                    } catch let error as ClaudeOAuthCredentialsError {
                        if case .notFound = error {
                            threwNotFound = true
                        } else {
                            throw error
                        }
                    }

                    #expect(threwNotFound == true)
                    #expect(securityReadCalls.hits < 1)
                }
            }
        }
    }
}
