# hackmyagent secure on a sample agent project: the scan, then the fix run.
# Render inside the docs-record container; docs/vhs/secure.json names the build it ran.
# Record: docs/vhs/record-secure.sh
# Both reports are longer than the terminal. The first is held one screen at a time, top to
# bottom; the second is held on its last screen, the fix summary. docs/vhs/secure-capture.txt
# carries both in full.
Output docs/vhs/secure.gif
Output docs/vhs/out/secure.mp4
Require npx
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
Type "bash docs/vhs/setup-lab.sh /work/hma-demo >/dev/null 2>&1 && cd /work/hma-demo && clear"
Enter
Wait@30s
Show
Sleep 1s
Type "npx hackmyagent secure"
Sleep 300ms
Enter
Wait@60s
ScrollUp@1ms 100
Sleep 500ms
Screenshot docs/vhs/secure-report.png
Sleep 4s
ScrollDown@1ms 38
Sleep 3500ms
ScrollDown@1ms 38
Sleep 3500ms
ScrollDown@1ms 38
Sleep 3500ms
Type "npx hackmyagent secure --fix"
Sleep 300ms
Enter
Wait@60s
Sleep 500ms
Screenshot docs/vhs/secure-fix.png
Sleep 6s
