# hackmyagent detect on five sample agent projects: the workspace root, then the worst project.
# Render inside the docs-record container from the published hackmyagent@0.33.0 (see docs/vhs/detect.json).
# Record: docs/vhs/record-detect.sh <path-to-demo-agents-checkout>
Output docs/vhs/detect.gif
Output docs/vhs/detect.mp4
Require hackmyagent
Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Columns 120
Set Rows 40
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 10
Set CursorBlink false

Hide
Type "cd ${HMA_DEMO_DIR:-/work/demo-agents} && clear"
Enter
Show
Sleep 1s
Type "npx hackmyagent detect"
Sleep 300ms
Enter
Sleep 3s
Sleep 2s
ScrollUp@1ms 100
Sleep 1s
Screenshot docs/vhs/detect-inventory.png
Sleep 4s
Type "npx hackmyagent detect deploy-runbook-agent"
Sleep 300ms
Enter
Sleep 3s
Sleep 1s
Screenshot docs/vhs/detect-path-forward.png
Sleep 4s
