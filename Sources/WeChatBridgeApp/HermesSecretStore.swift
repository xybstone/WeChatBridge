import Foundation
import Security

/// The Hermes webhook secret, stored in the Keychain rather than UserDefaults.
///
/// The URL is configuration and lives in `Preferences`; the secret is a
/// credential, and a credential that lands in `~/Library/Preferences` is one
/// Time Machine snapshot away from being committed somewhere. The generic
/// password item is owned by the app and never leaves the login keychain.
enum HermesSecretStore {
    /// Matches the app's own reverse-DNS prefix.
    private static let service = "com.xiangming.wechatbridge.hermes"

    enum StoreError: Error, Equatable {
        case unexpectedStatus(OSStatus)
    }

    /// Reads the stored secret. Nil when none was ever saved — the same answer
    /// as "cannot access the keychain", because the remedy in both cases is the
    /// settings pane asking for it again.
    static func read() -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else { return nil }
        return item as? Data
    }

    /// Writes the secret, replacing any previous value. An empty secret is a
    /// delete: clearing the field in 设置 must actually clear it.
    static func write(_ secret: Data) throws {
        guard !secret.isEmpty else {
            try remove()
            return
        }
        let update = baseQuery
        let attributes: [String: Any] = [kSecValueData as String: secret]
        var status = SecItemUpdate(update as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = update
            add[kSecValueData as String] = secret
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw StoreError.unexpectedStatus(status) }
    }

    static func remove() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw StoreError.unexpectedStatus(status)
        }
    }

    private static var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "hermes-webhook",
        ]
    }
}
