import Foundation
import Testing
@testable import CodexBarCore

@Suite(.serialized)
struct ClaudeOAuthDelegatedRefreshProfileIsolationTests {
    @Test
    func `overlapping profiles run their own delegated refresh in profile order`() async {
        ClaudeOAuthDelegatedRefreshCoordinator.resetForTesting()
        defer { ClaudeOAuthDelegatedRefreshCoordinator.resetForTesting() }

        actor Gate {
            private var startedContinuation: CheckedContinuation<Void, Never>?
            private var releaseContinuation: CheckedContinuation<Void, Never>?
            private var hasStarted = false
            private var isReleased = false

            func markStarted() {
                self.hasStarted = true
                self.startedContinuation?.resume()
                self.startedContinuation = nil
            }

            func waitStarted() async {
                if self.hasStarted { return }
                await withCheckedContinuation { self.startedContinuation = $0 }
            }

            func release() {
                self.isReleased = true
                self.releaseContinuation?.resume()
                self.releaseContinuation = nil
            }

            func waitRelease() async {
                if self.isReleased { return }
                await withCheckedContinuation { self.releaseContinuation = $0 }
            }
        }

        final class State: @unchecked Sendable {
            private let lock = NSLock()
            private var revision = 1
            private var touchedProfiles: [String] = []
            private var currentKeychainProfile: String?
            private var cachedKeychainProfileByProfile: [String: String] = [:]

            func touch(profile: String) -> Int {
                self.lock.withLock {
                    self.touchedProfiles.append(profile)
                    return self.touchedProfiles.count
                }
            }

            func finishTouch(profile: String) {
                self.lock.withLock {
                    self.currentKeychainProfile = profile
                    self.revision += 1
                }
            }

            func sync(profile: String) -> Bool {
                self.lock.withLock {
                    guard let currentKeychainProfile else { return false }
                    self.cachedKeychainProfileByProfile[profile] = currentKeychainProfile
                    return true
                }
            }

            func fingerprint() -> ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint {
                self.lock.withLock {
                    ClaudeOAuthCredentialsStore.ClaudeKeychainFingerprint(
                        modifiedAt: self.revision,
                        createdAt: 1,
                        persistentRefHash: "ref-\(self.revision)")
                }
            }

            func profiles() -> [String] {
                self.lock.withLock { self.touchedProfiles }
            }

            func cachedKeychainProfile(for profile: String) -> String? {
                self.lock.withLock { self.cachedKeychainProfileByProfile[profile] }
            }
        }

        let gate = Gate()
        let state = State()
        let profileA = "/tmp/codexbar-coordinator-profile-a"
        let profileB = "/tmp/codexbar-coordinator-profile-b"
        let environmentA = ["CLAUDE_CONFIG_DIR": profileA]
        let environmentB = ["CLAUDE_CONFIG_DIR": profileB]
        let now = Date(timeIntervalSince1970: 50500)
        let outcomes = await ClaudeOAuthCredentialsStore.withEnvironmentCredentialsURLForTesting {
            await KeychainAccessGate.withTaskOverrideForTesting(false) {
                await ClaudeOAuthKeychainPromptPreference.withTaskOverrideForTesting(.always) {
                    await ClaudeOAuthKeychainReadStrategyPreference.withTaskOverrideForTesting(.securityFramework) {
                        await ClaudeOAuthDelegatedRefreshCoordinator.withIsolatedStateForTesting {
                            await ClaudeOAuthDelegatedRefreshCoordinator.withCLIAvailableOverrideForTesting(true) {
                                await ClaudeOAuthDelegatedRefreshCoordinator.withTouchAuthPathOverrideForTesting
                                    { _, environment in
                                        let profile = environment["CLAUDE_CONFIG_DIR"] ?? ""
                                        if state.touch(profile: profile) == 1 {
                                            await gate.markStarted()
                                            await gate.waitRelease()
                                        }
                                        state.finishTouch(profile: profile)
                                    } operation: {
                                        await ClaudeOAuthDelegatedRefreshCoordinator
                                            .withSyncAfterRefreshOverrideForTesting { _, environment in
                                                state.sync(profile: environment["CLAUDE_CONFIG_DIR"] ?? "")
                                            } operation: {
                                                await ClaudeOAuthDelegatedRefreshCoordinator
                                                    .withKeychainFingerprintOverrideForTesting {
                                                        state.fingerprint()
                                                    }
                                                    operation: {
                                                        let first = Task {
                                                            await ClaudeOAuthDelegatedRefreshCoordinator.attempt(
                                                                now: now,
                                                                timeout: 2,
                                                                environment: environmentA)
                                                        }
                                                        await gate.waitStarted()
                                                        let second = Task {
                                                            await ClaudeOAuthDelegatedRefreshCoordinator.attempt(
                                                                now: now,
                                                                timeout: 2,
                                                                environment: environmentB)
                                                        }

                                                        await Task.yield()
                                                        #expect(state.profiles() == [profileA])
                                                        await gate.release()
                                                        return await (first.value, second.value)
                                                    }
                                            }
                                    }
                            }
                        }
                    }
                }
            }
        }

        #expect(outcomes.0 == .attemptedSucceededAndSynced)
        #expect(outcomes.1 == .attemptedSucceededAndSynced)
        #expect(state.profiles() == [profileA, profileB])
        #expect(state.cachedKeychainProfile(for: profileA) == profileA)
        #expect(state.cachedKeychainProfile(for: profileB) == profileB)
    }
}
