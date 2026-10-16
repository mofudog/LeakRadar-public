# 情報漏洩チェック Ver 1.1.1
制作 mofu / Copyright 2026 mofu

企業の公表資料を探し、対象の登録・利用条件を確認する無料・広告なしの静的サイトです。個人の漏洩有無を判定するものではありません。ヘルプ・免責事項は dist/help.html と dist/about.html にあります。

## 自動更新
GitHub Actionsが毎時17分に登録した公式資料と公式サイトを確認します。定刻実行・網羅性は保証されません。GitHubの遅延・停止や取得制限があります。新着は「自動取得・未整理」、既存資料の変更は「再確認待ち」と区別します。対象条件を推測で生成しません。登録先以外の全企業を自動発見する仕組みではありません。

データの原本: data/reviewed-incidents.json。監視先: data/monitor-sources.json。内容を確認した後に要約と確認日を更新してください。既存URLの本文を再確認した場合だけ data/reviewed-source-hashes.json にそのURLと確認済みハッシュを記録します。

## 公開
GitHub Pages の Source を GitHub Actions に設定します。標準の公開リポジトリと無料サブドメインを使用し、有料API・広告・独自ドメインは使いません。提供元の料金・制限変更には従う必要があります。

公開対象は dist のみ。SECURITY.md の注意を確認してください。GitHubにソースを公開する場合は公開リポジトリ内のすべてのファイルとコミット履歴が閲覧されます。

公開前の確認:
```
python scripts/audit_public_files.py
python scripts/validate_site.py
```
