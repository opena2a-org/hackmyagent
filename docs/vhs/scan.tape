# hackmyagent secure -- Security scan with findings
# Records: full scan with findings and recommendations

Output docs/vhs/scan.gif

Require hackmyagent

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 650
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set FontFamily "JetBrains Mono"

# Set up the demo project (hidden)
Hide
Type "bash docs/vhs/setup-lab.sh 2>/dev/null"
Enter
Sleep 1s
Type "cd /tmp/hma-demo && clear"
Enter
Sleep 500ms
Show

# Run security scan
Type "# Scan an AI agent project for security issues"
Enter
Sleep 1.5s

Type "hackmyagent secure"
Enter
Sleep 6s

# Pause for viewers to read findings
Sleep 8s
