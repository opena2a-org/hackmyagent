# hackmyagent attack -- red-team a live DVAA agent (the "break it in DVAA,
# scan it with HackMyAgent" pairing). Requires a DVAA fleet on :7003.
#   docker run -p 7001-7008:7001-7008 -p 7010-7016:7010-7016 \
#     -p 7020-7021:7020-7021 -p 9000:9000 opena2a/dvaa:0.9.1
# Render: vhs docs/vhs/attack-dvaa.tape  (then speed up with ffmpeg, see README of this dir)
Output docs/vhs/attack-dvaa-raw.gif

Set Shell "bash"
Set Width 1020
Set Height 760
Set FontSize 15
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Padding 18
Set Framerate 24

Hide
Type "cd ~/workspace/opena2a-org/hackmyagent && alias hackmyagent='node dist/cli.js' && clear"
Enter
Sleep 500ms
Show

Sleep 700ms
Type "# Break an agent in DVAA, then red-team it with HackMyAgent"
Enter
Sleep 1.2s
Type "hackmyagent attack http://localhost:7003/v1/chat/completions --api-format openai --intensity passive | head -29"
Sleep 500ms
Enter
Sleep 33s
Sleep 4s
