import CodexBarCore
import Foundation
import Testing
@testable import CodexBar

struct ClaudeActiveAccountProbeTests {
    @Test
    func `account corroboration follows the selected claude profile`() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("codexbar-claude-account-\(UUID().uuidString)", isDirectory: true)
        let profileA = root.appendingPathComponent("profile-a", isDirectory: true)
        let profileB = root.appendingPathComponent("profile-b", isDirectory: true)
        let customHome = root.appendingPathComponent("home", isDirectory: true)
        try FileManager.default.createDirectory(at: profileA, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: profileB, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: customHome, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        try Data(#"{"oauthAccount":{"accountUuid":"uuid-A"}}"#.utf8)
            .write(to: profileA.appendingPathComponent(".config.json"))
        try Data(#"{"oauthAccount":{"accountUuid":"uuid-B"}}"#.utf8)
            .write(to: profileB.appendingPathComponent(".config.json"))
        try Data(#"{"oauthAccount":{"accountUuid":"uuid-home"}}"#.utf8)
            .write(to: customHome.appendingPathComponent(".claude.json"))

        #expect(UsageStore.activeClaudeAccountUuid(environment: [
            ClaudeConfigPaths.configDirectoryEnvironmentKey: profileA.path,
        ]) == "uuid-A")
        #expect(UsageStore.activeClaudeAccountUuid(environment: [
            ClaudeConfigPaths.configDirectoryEnvironmentKey: profileB.path,
        ]) == "uuid-B")
        #expect(UsageStore.activeClaudeAccountUuid(environment: ["HOME": customHome.path]) == "uuid-home")
    }
}
