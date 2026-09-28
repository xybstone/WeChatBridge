import AppKit
import WeChatBridgeCore
import SwiftUI

/// What the Share menu offers, and the switches that decide which of it shows.
///
/// The list itself is fixed at build time — macOS builds that menu from signed
/// extension bundles — but which entries are live is the user's call, and it is
/// made here rather than three panes deep in System Settings. See
/// `ShareEntryProbe` for why the app is not sandboxed.
struct EntriesPane: View {
    @ObservedObject var targets: ForwardTargets
    @ObservedObject var preferences: Preferences
    @StateObject private var probe = ShareEntryProbe()
    @State private var configuration: EntryConfiguration?

    /// The secret field's own text. Deliberately not prefilled from the
    /// Keychain: the credential is write-only as far as the UI is concerned,
    /// and an empty field with a saved secret is the honest rendering of that.
    @State private var hermesSecretField = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Space.section) {
            Text(L10n.text("选择要出现在微信「转发到其他应用」里的操作。"))
                .font(Typo.paneBody)
                .foregroundStyle(Theme.inkSecondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 460, alignment: .leading)

            ShareEntryList(
                probe: probe,
                compactDetails: true,
                obsidianVaultPath: preferences.obsidianVaultPath,
                hermesWebhookURL: preferences.hermesWebhookURL,
                customTargetCount: targets.targets.count
            ) { action in
                switch action {
                case .obsidian: configuration = .obsidian
                case .hermes: configuration = .hermes
                case .custom: configuration = .custom
                default: break
                }
            }

            Button {
                LoginItem.openExtensionsSettings()
            } label: {
                Label(L10n.text("入口没有出现在微信菜单里？"), systemImage: "questionmark.circle")
                    .font(Typo.paneCaption)
                    .foregroundStyle(Theme.systemBlue)
            }
            .buttonStyle(PlainPressButtonStyle(staticFeedback: true))
            .accessibilityIdentifier("entries.system-settings")
        }
        .sheet(item: $configuration) { item in
            VStack(alignment: .leading, spacing: Space.xl) {
                HStack {
                    Text(item.title)
                        .font(Typo.paneTitle)
                        .foregroundStyle(Theme.ink)
                    Spacer(minLength: Space.l)
                    Button(L10n.text("完成")) { configuration = nil }
                        .buttonStyle(SettingsActionButtonStyle())
                        .keyboardShortcut(.defaultAction)
                }

                switch item {
                case .obsidian:
                    obsidianSettings
                case .hermes:
                    hermesSettings
                case .custom:
                    ForwardTargetList(targets: targets)
                }
            }
            .padding(Space.xl)
            .frame(width: 540)
            .frame(minHeight: 220, alignment: .topLeading)
        }
        .onAppear { probe.refresh() }
        // The entries can still be changed in System Settings, and the user
        // comes straight back afterwards, so this is re-read on every
        // activation rather than once.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            probe.refresh()
        }
    }

    private var obsidianSettings: some View {
        VStack(spacing: 0) {
            SettingRow(
                title: L10n.text("知识库文件夹"),
                detail: preferences.obsidianVaultPath.map {
                    URL(fileURLWithPath: $0, isDirectory: true).lastPathComponent
                } ?? L10n.text("尚未选择"),
                alignment: .center
            ) {
                HStack(spacing: Space.s) {
                    if let path = preferences.obsidianVaultPath {
                        Button(L10n.text("在 Finder 中显示")) {
                            NSWorkspace.shared.activateFileViewerSelecting([
                                URL(fileURLWithPath: path, isDirectory: true)
                            ])
                        }
                        .buttonStyle(SettingsActionButtonStyle())
                    }
                    Button(L10n.text("选择文件夹…")) { chooseObsidianVault() }
                        .buttonStyle(SettingsActionButtonStyle())
                }
            }
            .padding(Space.m)

            Rectangle()
                .fill(Theme.stroke)
                .frame(height: Stroke.hairline)
                .padding(.leading, Space.m)

            SettingRow(
                title: L10n.text("子文件夹"),
                detail: L10n.text("聊天 Markdown 与原始 ZIP 会写入这个目录。"),
                alignment: .center
            ) {
                TextField(L10n.text("子文件夹"), text: $preferences.obsidianSubfolder)
                    .textFieldStyle(SettingsTextFieldStyle())
                    .frame(width: SettingsControlMetrics.actionWidth)
            }
            .padding(Space.m)
        }
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
                .strokeBorder(Theme.stroke, lineWidth: Stroke.hairline)
        )
    }

    private func chooseObsidianVault() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.prompt = L10n.text("选择知识库")
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        preferences.obsidianVaultPath = folder.path
    }

    // MARK: - Hermes

    /// The URL is configuration and is saved as pasted; the secret is a
    /// credential and goes straight from the field into the Keychain, never
    /// through `Preferences` or any file the app writes.
    private var hermesSettings: some View {
        VStack(spacing: 0) {
            SettingRow(
                title: L10n.text("Webhook 地址"),
                detail: hermesURLDetail,
                alignment: .center
            ) {
                TextField(
                    L10n.text("例如 http://127.0.0.1:8644/webhooks/wechat"),
                    text: Binding(
                        get: { preferences.hermesWebhookURL ?? "" },
                        set: { preferences.hermesWebhookURL = $0.isEmpty ? nil : $0 }
                    )
                )
                .textFieldStyle(SettingsTextFieldStyle())
                .frame(width: SettingsControlMetrics.actionWidth)
            }
            .padding(Space.m)

            Rectangle()
                .fill(Theme.stroke)
                .frame(height: Stroke.hairline)
                .padding(.leading, Space.m)

            SettingRow(
                title: L10n.text("HMAC 密钥"),
                detail: L10n.text("只保存在钥匙串里，不会写入文件或日志。"),
                alignment: .center
            ) {
                SecureField(L10n.text("粘贴路由的 secret"), text: $hermesSecretField)
                    .textFieldStyle(SettingsTextFieldStyle())
                    .frame(width: SettingsControlMetrics.actionWidth)
                    .onChange(of: hermesSecretField) { _, newValue in
                        try? HermesSecretStore.write(Data(newValue.trimmingCharacters(in: .whitespacesAndNewlines).utf8))
                    }
            }
            .padding(Space.m)

            Rectangle()
                .fill(Theme.stroke)
                .frame(height: Stroke.hairline)
                .padding(.leading, Space.m)

            SettingRow(
                title: L10n.text("投递方式"),
                detail: L10n.text("发送批次编号、聊天名与归档在本机的路径；聊天内容不会离开这台 Mac，也不会自动回复微信。"),
                alignment: .center
            ) {}
            .padding(Space.m)
        }
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.card, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: Radius.card, style: .continuous)
                .strokeBorder(Theme.stroke, lineWidth: Stroke.hairline)
        )
    }

    private var hermesURLDetail: String {
        switch HermesDelivery.validatedURL(preferences.hermesWebhookURL) {
        case .success: return L10n.text("已配置")
        case .failure(.notConfigured): return L10n.text("尚未填写")
        case .failure(.notLoopback): return L10n.text("只允许指向本机的地址")
        case .failure: return L10n.text("地址无效")
        }
    }
}

private enum EntryConfiguration: String, Identifiable {
    case obsidian
    case hermes
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .obsidian: L10n.text("Obsidian 沉淀")
        case .hermes: L10n.text("发给 Hermes")
        case .custom: L10n.text("「发送到自定义」的应用")
        }
    }
}
