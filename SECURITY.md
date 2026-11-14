# セキュリティの問題を見つけたとき / Reporting a vulnerability

**公開の Issue には書かないでください。** 直す前に広まると、使っている人が危険にさらされます。

GitHub のこのリポジトリの「Security」タブ →「Report a vulnerability」から、非公開で知らせてください（GitHub の Private vulnerability reporting）。

- 書いてほしいこと：どの版（コミット）か、再現の手順、起きること、考えられる影響
- 返事の目安：数日以内に受け取ったことを返します。個人で開発しているため、直すまでの時間はお約束できません。
- 直したあと、知らせてくれた方のお名前（希望されれば）を変更の記録に載せます。

Please do **not** open a public issue for security problems. Use GitHub's private vulnerability reporting
(the "Security" tab → "Report a vulnerability") and include the affected commit, steps to reproduce and the impact.
This is a personal project, so response times are best effort.

## 対象 / Scope

- `pkvault/`（サーバーの部品）と `static/pkvault/`（ブラウザーの部品）
- `sample/` は見本です。見本そのものの作りの問題も歓迎します。

この部品の設計上、守れないもの（README の「守れること・守れないこと」）は、脆弱性としては扱いません。
