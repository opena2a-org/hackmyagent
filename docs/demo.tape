# HackMyAgent — 204 security checks scanning a vulnerable project
# Run: vhs docs/demo.tape

Output docs/hackmyagent-demo.gif

Set Width 880
Set Height 580
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms
Set Padding 15

Hide
Type "cd /Users/ecolibria/workspace/opena2a-org/test/hma && clear"
Enter
Sleep 500ms
Show

Sleep 1s
Type "npx hackmyagent secure 2>&1 | head -30"
Enter
Sleep 8s

Sleep 6s
