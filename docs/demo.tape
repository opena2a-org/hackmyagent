# HackMyAgent Demo
# Security scanner for AI agents -- 147 checks, attack mode, auto-fix
# Run: vhs docs/demo.tape

Output docs/hackmyagent-demo.gif

Set Width 1200
Set Height 600
Set FontSize 20
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 30
Set PlaybackSpeed 1.0

# Hidden setup: navigate to a project directory
Hide
Type "cd /tmp/demo-project && clear"
Enter
Sleep 500ms
Show

# Title pause
Sleep 1s

# Step 1: Run security scan with 147 checks
Type "npx hackmyagent secure ."
Enter
Sleep 6s

# Let users read the findings
Sleep 3s

# Step 2: Auto-fix the issues
Type "npx hackmyagent secure . --fix"
Enter
Sleep 6s

# Let users read the fix results
Sleep 3s

# Step 3: Attack mode (local simulation)
Type "npx hackmyagent attack --local --intensity active"
Enter
Sleep 8s

# Final pause to read attack results
Sleep 3s
