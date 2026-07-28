import Foundation
import Security
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct ClaudeOAuthCredentialsStoreNeverPromptCacheTests {
    private struct TestState {
        let pendingStore: ClaudeOAuthCredentialsStore.PendingCacheClearMemoryStore
        let recorder: ClaudeOAuthCredentialsStore.OAuthCacheOperationRecorder

        var cacheKey: KeychainCacheStore.Key {
            ClaudeOAuthCredentialsStore.cacheKeyForTesting(
                profileIdentifier: ClaudeOAuthCredentialsStore.credentialsProfileIdentifier(environment: [:]))
        }
    }

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

    private func withTestState<T>(_ operation: (TestState) throws -> T) throws -> T {
        let service = "com.steipete.codexbar.cache.tests.\(UUID().uuidString)"
        let pendingStore = ClaudeOAuthCredentialsStore.PendingCacheClearMemoryStore()
        let recorder = ClaudeOAuthCredentialsStore.OAuthCacheOperationRecorder()
        let fingerprintStore = ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprintStore()
        let state = TestState(pendingStore: pendingStore, recorder: recorder)

        return try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(false) {
            try KeychainCacheStore.withServiceOverrideForTesting(service) {
                KeychainCacheStore.setTestStoreForTesting(true)
                defer { KeychainCacheStore.setTestStoreForTesting(false) }

                return try KeychainAccessGate.withTaskOverrideForTesting(false) {
                    try ClaudeOAuthCredentialsStore.withKeychainAccessOverrideForTesting(false) {
                        try ClaudeOAuthCredentialsStore.withPendingCacheClearStoreOverrideForTesting(pendingStore) {
                            try ClaudeOAuthCredentialsStore.withOAuthCacheOperationRecorderForTesting(recorder) {
                                try ClaudeOAuthCredentialsStore.withIsolatedMemoryCacheForTesting {
                                    try ClaudeOAuthCredentialsStore.withIsolatedCredentialsFileTrackingForTesting {
                                        try ClaudeOAuthCredentialsStore
                                            .withClaudeKeychainFingerprintStoreOverrideForTesting(fingerprintStore) {
                                                try operation(state)
                                            }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private func withCredentialsFile<T>(
        data: Data?,
        operation: (URL) throws -> T) throws -> T
    {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let fileURL = tempDirectory.appendingPathComponent("credentials.json")
        if let data {
            try data.write(to: fileURL)
        }
        return try ClaudeOAuthCredentialsStore.withCredentialsURLOverrideForTesting(fileURL) {
            try operation(fileURL)
        }
    }

    private func seedCache(
        _ state: TestState,
        accessToken: String,
        storedAt: Date = Date())
    {
        let data = self.makeCredentialsData(
            accessToken: accessToken,
            expiresAt: Date(timeIntervalSinceNow: 3600))
        let stored = ClaudeOAuthCredentialsStore.withOAuthCacheOperationRecorderForTesting(nil) {
            KeychainCacheStore.storeResult(
                key: state.cacheKey,
                entry: ClaudeOAuthCredentialsStore.CacheEntry(data: data, storedAt: storedAt))
        }
        #expect(stored)
    }

    private func cachedToken(_ state: TestState) throws -> String? {
        try ClaudeOAuthCredentialsStore.withOAuthCacheOperationRecorderForTesting(nil) {
            switch KeychainCacheStore.load(
                key: state.cacheKey,
                as: ClaudeOAuthCredentialsStore.CacheEntry.self)
            {
            case let .found(entry):
                return try ClaudeOAuthCredentials.parse(data: entry.data).accessToken
            case .missing:
                return nil
            case .invalid, .temporarilyUnavailable:
                Issue.record("Expected a valid or missing test cache entry")
                return nil
            }
        }
    }

    private func runDefaults(_ arguments: [String]) throws -> (status: Int32, output: String) {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/defaults")
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    @Test
    func `owned cache disabled loads the credentials file with zero oauth cache IO`() throws {
        try self.withTestState { state in
            let fileData = self.makeCredentialsData(
                accessToken: "file-token",
                expiresAt: Date(timeIntervalSinceNow: 3600))
            try self.withCredentialsFile(data: fileData) { _ in
                self.seedCache(state, accessToken: "cached-token")

                let credentials = try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    try ProviderInteractionContext.$current.withValue(.background) {
                        try ClaudeOAuthCredentialsStore.load(environment: [:], allowKeychainPrompt: false)
                    }
                }

                #expect(credentials.accessToken == "file-token")
                #expect(state.recorder.operations.isEmpty)
                #expect(state.pendingStore.isPending)
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")
            }
        }
    }

    @Test
    func `owned cache disabled file invalidation records a tombstone without oauth cache IO`() throws {
        try self.withTestState { state in
            let initialData = self.makeCredentialsData(
                accessToken: "initial-token",
                expiresAt: Date(timeIntervalSinceNow: 3600))
            try self.withCredentialsFile(data: initialData) { fileURL in
                self.seedCache(state, accessToken: "cached-token")

                let initialChange = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCacheIfCredentialsFileChanged()
                }
                #expect(initialChange)

                let updatedData = self.makeCredentialsData(
                    accessToken: "updated-token-with-a-different-size",
                    expiresAt: Date(timeIntervalSinceNow: 7200))
                try updatedData.write(to: fileURL)

                let changed = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCacheIfCredentialsFileChanged()
                }
                let changedAgain = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCacheIfCredentialsFileChanged()
                }

                #expect(changed)
                #expect(!changedAgain)
                #expect(state.recorder.operations.isEmpty)
                #expect(state.pendingStore.isPending)
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")
            }
        }
    }

    @Test
    func `owned cache disabled has cached credentials ignores stale oauth cache with zero IO`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")

                let hasCached = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ProviderInteractionContext.$current.withValue(.background) {
                        ClaudeOAuthCredentialsStore.hasCachedCredentials(environment: [:])
                    }
                }

                #expect(!hasCached)
                #expect(state.recorder.operations.isEmpty)
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")
            }
        }
    }

    @Test
    func `has cached credentials ignores stale oauth cache when pending clear fails`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                }

                let hasCached = KeychainCacheStore.withClearFailureStatusOverrideForTesting(
                    errSecInteractionNotAllowed)
                {
                    ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                            ProviderInteractionContext.$current.withValue(.background) {
                                ClaudeOAuthCredentialsStore.hasCachedCredentials(environment: [:])
                            }
                        }
                    }
                }

                #expect(!hasCached)
                #expect(state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear])
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")
            }
        }
    }

    @Test
    func `reenabling owned cache clears stale entry before repopulating from file`() throws {
        try self.withTestState { state in
            let fileData = self.makeCredentialsData(
                accessToken: "file-token-new",
                expiresAt: Date(timeIntervalSinceNow: 3600))
            try self.withCredentialsFile(data: fileData) { _ in
                self.seedCache(
                    state,
                    accessToken: "cached-token",
                    storedAt: Date(timeIntervalSince1970: 0))

                _ = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCacheIfCredentialsFileChanged()
                }
                #expect(state.pendingStore.isPending)
                #expect(state.recorder.operations.isEmpty)

                let credentials = try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                    try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                        try ProviderInteractionContext.$current.withValue(.background) {
                            try ClaudeOAuthCredentialsStore.load(environment: [:], allowKeychainPrompt: false)
                        }
                    }
                }

                #expect(credentials.accessToken == "file-token-new")
                #expect(!state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear, .load, .load, .store])
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "file-token-new")
            }
        }
    }

    @Test
    func `invalidation while owned cache disabled clears stale cache after reenable`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")

                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                }
                #expect(state.pendingStore.isPending)
                #expect(state.recorder.operations.isEmpty)
                let staleToken = try self.cachedToken(state)
                #expect(staleToken == "cached-token")

                do {
                    _ = try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                            try ProviderInteractionContext.$current.withValue(.background) {
                                try ClaudeOAuthCredentialsStore.load(environment: [:], allowKeychainPrompt: false)
                            }
                        }
                    }
                    Issue.record("Expected ClaudeOAuthCredentialsError.notFound")
                } catch let error as ClaudeOAuthCredentialsError {
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(error)")
                        return
                    }
                }

                #expect(!state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear, .load, .load])
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == nil)
            }
        }
    }

    @Test
    func `pending oauth cache clear retries after a temporarily unavailable delete`() throws {
        try self.withTestState { state in
            let fileData = self.makeCredentialsData(
                accessToken: "file-token-new",
                expiresAt: Date(timeIntervalSinceNow: 3600))
            try self.withCredentialsFile(data: fileData) { _ in
                self.seedCache(state, accessToken: "cached-token")
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                }

                let first = try KeychainCacheStore.withClearFailureStatusOverrideForTesting(
                    errSecInteractionNotAllowed)
                {
                    try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                            try ProviderInteractionContext.$current.withValue(.background) {
                                try ClaudeOAuthCredentialsStore.load(environment: [:], allowKeychainPrompt: false)
                            }
                        }
                    }
                }
                #expect(first.accessToken == "file-token-new")
                #expect(state.pendingStore.isPending)
                let staleToken = try self.cachedToken(state)
                #expect(staleToken == "cached-token")

                let second = try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                    try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                        try ProviderInteractionContext.$current.withValue(.background) {
                            try ClaudeOAuthCredentialsStore.load(environment: [:], allowKeychainPrompt: false)
                        }
                    }
                }
                #expect(second.accessToken == "file-token-new")
                #expect(!state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear, .clear, .load, .load, .store])
                let refreshedToken = try self.cachedToken(state)
                #expect(refreshedToken == "file-token-new")
            }
        }
    }

    @Test
    func `replacement store failure after successful clear keeps tombstone and cache missing`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                }

                let syncData = self.makeCredentialsData(
                    accessToken: "sync-token",
                    expiresAt: Date(timeIntervalSinceNow: 3600),
                    refreshToken: "sync-refresh-token")
                let synced = KeychainCacheStore.withStoreFailureStatusOverrideForTesting(
                    errSecInteractionNotAllowed)
                {
                    ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                            ProviderInteractionContext.$current.withValue(.userInitiated) {
                                ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                    data: syncData,
                                    fingerprint: nil)
                                {
                                    ClaudeOAuthCredentialsStore.syncFromClaudeKeychainAfterDelegatedRefresh()
                                }
                            }
                        }
                    }
                }

                #expect(synced)
                #expect(state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear, .store])
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == nil)
            }
        }
    }

    @Test
    func `failed clear preserves the tombstone and stale cache without replacement`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")
                ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.invalidateCache()
                }

                let syncData = self.makeCredentialsData(
                    accessToken: "sync-token",
                    expiresAt: Date(timeIntervalSinceNow: 3600),
                    refreshToken: "sync-refresh-token")
                let synced = KeychainCacheStore.withClearFailureStatusOverrideForTesting(
                    errSecInteractionNotAllowed)
                {
                    ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.onlyOnUserAction) {
                            ProviderInteractionContext.$current.withValue(.userInitiated) {
                                ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                    data: syncData,
                                    fingerprint: nil)
                                {
                                    ClaudeOAuthCredentialsStore.syncFromClaudeKeychainAfterDelegatedRefresh()
                                }
                            }
                        }
                    }
                }

                #expect(synced)
                #expect(state.pendingStore.isPending)
                #expect(state.recorder.operations == [.clear])
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")
            }
        }
    }

    @Test
    func `bundled CLI resolves the owning app prompt policy domain`() throws {
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let appURL = tempDirectory.appendingPathComponent("CodexBar.app", isDirectory: true)
        let contentsURL = appURL.appendingPathComponent("Contents", isDirectory: true)
        let helpersURL = contentsURL.appendingPathComponent("Helpers", isDirectory: true)
        let macOSURL = contentsURL.appendingPathComponent("MacOS", isDirectory: true)
        let binURL = tempDirectory.appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: helpersURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: macOSURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: binURL, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDirectory) }

        let info: [String: Any] = [
            "CFBundleExecutable": "CodexBar",
            "CFBundleIdentifier": ClaudeOAuthKeychainPromptPreference.debugApplicationDefaultsDomain,
            "CFBundlePackageType": "APPL",
        ]
        let infoData = try PropertyListSerialization.data(
            fromPropertyList: info,
            format: .xml,
            options: 0)
        try infoData.write(to: contentsURL.appendingPathComponent("Info.plist"))
        try Data().write(to: macOSURL.appendingPathComponent("CodexBar"))

        let helperURL = helpersURL.appendingPathComponent("CodexBarCLI")
        try Data().write(to: helperURL)
        let symlinkURL = binURL.appendingPathComponent("codexbar")
        try FileManager.default.createSymbolicLink(at: symlinkURL, withDestinationURL: helperURL)

        let bundledCLIDomain = ClaudeOAuthKeychainPromptPreference.resolveApplicationDefaultsDomain(
            bundleIdentifier: nil,
            bundleURL: nil,
            executableURL: nil,
            invocationURL: symlinkURL)
        #expect(bundledCLIDomain == ClaudeOAuthKeychainPromptPreference.debugApplicationDefaultsDomain)

        let debugWidgetDomain = ClaudeOAuthKeychainPromptPreference.resolveApplicationDefaultsDomain(
            bundleIdentifier: "com.steipete.codexbar.debug.widget",
            bundleURL: nil,
            executableURL: nil,
            invocationURL: nil)
        #expect(debugWidgetDomain == ClaudeOAuthKeychainPromptPreference.debugApplicationDefaultsDomain)

        let standaloneDomain = ClaudeOAuthKeychainPromptPreference.resolveApplicationDefaultsDomain(
            bundleIdentifier: nil,
            bundleURL: nil,
            executableURL: URL(fileURLWithPath: "/usr/local/bin/codexbar"),
            invocationURL: nil)
        #expect(standaloneDomain == ClaudeOAuthKeychainPromptPreference.releaseApplicationDefaultsDomain)

        let testProcessDomain = ClaudeOAuthKeychainPromptPreference.resolveApplicationDefaultsDomain(
            bundleIdentifier: nil,
            bundleURL: Bundle.main.bundleURL,
            executableURL: Bundle.main.executableURL,
            invocationURL: CommandLine.arguments.first.map(URL.init(fileURLWithPath:)),
            bundleIdentifierForApp: { _ in nil })
        #expect(testProcessDomain == ClaudeOAuthKeychainPromptPreference.releaseApplicationDefaultsDomain)
    }

    @Test
    func `shared tombstone propagates across process boundaries`() throws {
        let domain = "ClaudeOAuthPendingCacheTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let lockURL = tempDirectory.appendingPathComponent("cache.lock")
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: lockURL)
        store.markPending()

        let childRead = try self.runDefaults(["read", domain, key])
        #expect(childRead.status == 0)
        #expect(!childRead.output.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

        let childDelete = try self.runDefaults(["delete", domain, key])
        #expect(childDelete.status == 0)
        #expect(!store.isPending)

        let childWrite = try self.runDefaults(["write", domain, key, UUID().uuidString])
        #expect(childWrite.status == 0)
        #expect(store.isPending)

        store.withCacheTransaction { pending in
            pending = false
        }
        let childReadAfterResolution = try self.runDefaults(["read", domain, key])
        #expect(childReadAfterResolution.status != 0)
    }

    @Test
    func `newer tombstone survives an older cache transaction`() throws {
        let domain = "ClaudeOAuthPendingCacheRaceTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let lockURL = tempDirectory.appendingPathComponent("cache.lock")
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: lockURL)
        store.markPending()

        let newerGeneration = UUID().uuidString
        var childWriteStatus: Int32?
        store.withCacheTransaction { pending in
            childWriteStatus = try? self.runDefaults(["write", domain, key, newerGeneration]).status
            pending = false
        }
        userDefaults.synchronize()

        #expect(childWriteStatus == 0)
        #expect(userDefaults.string(forKey: key) == newerGeneration)
        #expect(store.isPending)
    }

    @Test
    func `profile tombstone leaves other profile transactions untouched`() throws {
        let domain = "ClaudeOAuthPendingCacheProfilesTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: tempDirectory.appendingPathComponent("cache.lock"))
        store.markPending(profileIdentifier: "profile-a")

        #expect(store.isPending(profileIdentifier: "profile-a"))
        #expect(!store.isPending(profileIdentifier: "profile-b"))
        store.withCacheTransaction(profileIdentifier: "profile-b") { pending in
            #expect(!pending)
        }
        #expect(store.isPending(profileIdentifier: "profile-a"))

        store.withCacheTransaction(profileIdentifier: "profile-a") { pending in
            #expect(pending)
            pending = false
        }
        #expect(!store.isPending)
    }

    @Test
    func `legacy cleanup tombstone persists for only its migration profile`() throws {
        let domain = "ClaudeOAuthPendingLegacyCleanupProfilesTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        let lockURL = tempDirectory.appendingPathComponent("cache.lock")
        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: lockURL)
        store.withCacheTransaction(
            profileIdentifier: "profile-a",
            includingLegacyCleanup: { profilePending, legacyCleanupPending in
                #expect(!profilePending)
                #expect(!legacyCleanupPending)
                legacyCleanupPending = true
            })

        let reloadedStore = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: lockURL)
        #expect(reloadedStore.isPending(profileIdentifier: "profile-a"))
        #expect(!reloadedStore.isPending(profileIdentifier: "profile-b"))
        reloadedStore.withCacheTransaction(
            profileIdentifier: "profile-b",
            includingLegacyCleanup: { profilePending, legacyCleanupPending in
                #expect(!profilePending)
                #expect(!legacyCleanupPending)
            })
        reloadedStore.withCacheTransaction(
            profileIdentifier: "profile-a",
            includingLegacyCleanup: { profilePending, legacyCleanupPending in
                #expect(!profilePending)
                #expect(legacyCleanupPending)
                legacyCleanupPending = false
            })
        #expect(!reloadedStore.isPending)
    }

    @Test
    func `legacy tombstone clears the legacy cache before profile migration`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                let legacyKey = KeychainCacheStore.Key.oauth(provider: .claude)
                let legacyStored = ClaudeOAuthCredentialsStore.withOAuthCacheOperationRecorderForTesting(nil) {
                    KeychainCacheStore.storeResult(
                        key: legacyKey,
                        entry: ClaudeOAuthCredentialsStore.CacheEntry(
                            data: self.makeCredentialsData(
                                accessToken: "legacy-token",
                                expiresAt: Date(timeIntervalSinceNow: 3600)),
                            storedAt: Date()))
                }
                #expect(legacyStored)
                state.pendingStore.markPending()

                do {
                    _ = try ClaudeOAuthCredentialsStore.withCodexBarOAuthCacheEnabledForTesting(true) {
                        try ClaudeOAuthCredentialsStore.loadRecord(
                            environment: [:],
                            allowKeychainPrompt: false,
                            allowClaudeKeychainRepairWithoutPrompt: false)
                    }
                    Issue.record("Expected the cleared legacy cache to leave no credentials")
                } catch let error as ClaudeOAuthCredentialsError {
                    guard case .notFound = error else {
                        Issue.record("Expected .notFound, got \(error)")
                        return
                    }
                }

                #expect(!state.pendingStore.isPending)
                let legacyLoad = ClaudeOAuthCredentialsStore.withOAuthCacheOperationRecorderForTesting(nil) {
                    KeychainCacheStore.load(key: legacyKey, as: ClaudeOAuthCredentialsStore.CacheEntry.self)
                }
                guard case .missing = legacyLoad else {
                    Issue.record("Expected the legacy cache to remain deleted")
                    return
                }
            }
        }
    }

    @Test
    func `legacy boolean tombstone remains pending until cache resolution`() throws {
        let domain = "ClaudeOAuthPendingCacheLegacyTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }
        userDefaults.set(true, forKey: key)
        userDefaults.synchronize()

        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: tempDirectory.appendingPathComponent("cache.lock"))
        #expect(store.isPending)
        store.withCacheTransaction { pending in
            pending = false
        }
        #expect(!store.isPending)
    }

    @Test
    func `cache transaction fails closed when its lock is unavailable`() throws {
        let domain = "ClaudeOAuthPendingCacheLockFailureTests.\(UUID().uuidString)"
        let key = "pending"
        let tempDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
        let nonDirectoryURL = tempDirectory.appendingPathComponent("not-a-directory")
        try Data().write(to: nonDirectoryURL)
        let userDefaults = try #require(UserDefaults(suiteName: domain))
        defer {
            userDefaults.removePersistentDomain(forName: domain)
            userDefaults.synchronize()
            try? FileManager.default.removeItem(at: tempDirectory)
        }

        let store = ClaudeOAuthPendingCacheClearUserDefaultsStore(
            domain: domain,
            key: key,
            lockURL: nonDirectoryURL.appendingPathComponent("cache.lock"))
        var operationCalled = false
        store.withCacheTransaction { _ in
            operationCalled = true
        }
        userDefaults.synchronize()

        #expect(!operationCalled)
        #expect(userDefaults.string(forKey: key) != nil)
        #expect(store.isPending)
    }

    @Test
    func `owned cache disabled still rejects ambient experimental repair`() throws {
        try self.withTestState { state in
            try self.withCredentialsFile(data: nil) { _ in
                self.seedCache(state, accessToken: "cached-token")
                let securityData = self.makeCredentialsData(
                    accessToken: "security-cli-token",
                    expiresAt: Date(timeIntervalSinceNow: 3600),
                    refreshToken: "security-cli-refresh-token")

                let error = #expect(throws: ClaudeOAuthCredentialsError.self) {
                    try ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(
                        .securityCLIExperimental)
                    {
                        try ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                            try ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(
                                .data(securityData))
                            {
                                try ClaudeOAuthCredentialsStore.withClaudeKeychainOverridesForTesting(
                                    data: securityData,
                                    fingerprint: nil)
                                {
                                    try ProviderInteractionContext.$current.withValue(.background) {
                                        try ClaudeOAuthCredentialsStore.load(
                                            environment: [:],
                                            allowKeychainPrompt: false)
                                    }
                                }
                            }
                        }
                    }
                }
                guard case .notFound = error else {
                    Issue.record("Expected .notFound, got \(String(describing: error))")
                    return
                }
                #expect(state.recorder.operations.isEmpty)
                #expect(!state.pendingStore.isPending)
                let cachedToken = try self.cachedToken(state)
                #expect(cachedToken == "cached-token")

                let mcpOnly = Data(#"{"mcpOAuth":{"plugin:test":{"accessToken":"synthetic"}}}"#.utf8)
                let isMcpOnly = ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.never) {
                    ClaudeOAuthCredentialsStore.withSecurityCLIReadOverrideForTesting(.data(mcpOnly)) {
                        ClaudeOAuthCredentialsStore.isMcpOAuthOnlyClaudeKeychainPayloadPresent(
                            interaction: .background,
                            readStrategy: .securityCLIExperimental,
                            keychainAccessDisabled: true,
                            environment: [
                                KeychainAccessGate.disableAccessEnvironmentKey: "1",
                                ClaudeOAuthCredentialsStore.isolatedSecurityCLIKeychainEnvironmentKey:
                                    "/tmp/codexbar-test.keychain-db",
                            ])
                    }
                }
                #expect(!isMcpOnly)
            }
        }
    }

    @Test
    func `persisted never preference keeps foreign keychain reads disabled`() throws {
        let suiteName = "ClaudeOAuthCredentialsStoreNeverPromptCacheTests.\(UUID().uuidString)"
        let userDefaults = try #require(UserDefaults(suiteName: suiteName))
        defer { userDefaults.removePersistentDomain(forName: suiteName) }
        userDefaults.set(ClaudeOAuthKeychainPromptMode.never.rawValue, forKey: "claudeOAuthKeychainPromptMode")

        #expect(ClaudeOAuthKeychainPromptPreference.storedMode(userDefaults: userDefaults) == .never)
        #expect(
            userDefaults.string(forKey: "claudeOAuthKeychainPromptMode")
                == ClaudeOAuthKeychainPromptMode.never.rawValue)
    }
}
