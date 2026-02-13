# mcp-ssh 技術仕様書

## 1. 役割と目的
AIエージェントがネットワーク上のリソースにアクセスする際の「安全な出口」として機能します。
- ユーザーの資格情報（パスワード等）をAIから隠蔽する。
- 実行前にDB制約のポリシーチェックを強制し、許可時のみSSH実行する。

## 2. 実行フロー

### ツール呼び出しフロー (ssh_exec via alias)
1. AIエージェントが `ssh_exec(alias: "web-server", command: "ls")` を呼び出す。
2. サーバーがリクエストをパースし、実行パスを決定。
3. `mcp-ssh-manager` DBからマシン情報・制約・認証情報を取得。
4. 制約を評価（未知ルールは fail-close で拒否）。
5. `rust-ssh` エンジンで実行し、実行結果（stdout/stderr）をJSON-RPCレスポンスとして返却。

## 3. 主要なデータ構造

### JsonRpcRequest / Response
MCP 標準に準拠したメッセージング構造。

### ツール定義
```json
{
  "name": "get_host_info",
  "description": "Get detailed context and rules for a strict SSH host by alias.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "alias": { "type": "string" }
    },
    "required": ["alias"]
  }
}
```

## 4. エラー処理と信頼性
- **デッドロック防止**: 非同期実行（Tokio）により、長時間かかるコマンドの実行中もサーバーの応答性を維持します。
- **監査ログ**: 成功時だけでなく接続失敗時も `command_logs` に記録します。

## 5. 関連コンポーネント
- **rust-ssh-engine**: 実際の接続・認証・コマンド実行を担当するコア。
- **mcp-ssh-manager**: マシン情報・制約・資格情報（暗号化）を管理するマスターDBの管理/GUI。
