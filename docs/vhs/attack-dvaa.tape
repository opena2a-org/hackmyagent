# hackmyagent attack -- red-team a live DVAA agent (the "break it in DVAA,
# scan it with HackMyAgent" pairing). Requires a DVAA fleet on :7003.
#   docker run -p 7001-7008:7001-7008 -p 7010-7016:7010-7016 \
#     -p 7020-7021:7020-7021 -p 9000:9000 opena2a/dvaa:0.9.1
# Render from the repository root after `npm run build`: vhs docs/vhs/attack-dvaa.tape
# The 28 passive attacks take over a minute against DVAA. The recording is hidden
# while they run and shown again once the report has printed, so the GIF cuts the
# wait; the Duration line in the report is the real run time.
# Text version of the same command: docs/vhs/attack-dvaa-capture.txt
Output docs/vhs/attack-dvaa.gif

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
Type "export OPENA2A_TELEMETRY=off && alias hackmyagent='node dist/cli.js' && clear"
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
Sleep 1s
Hide
Wait+Screen@4m /Fake Tool Detection/
Sleep 500ms
Show
Sleep 6s
