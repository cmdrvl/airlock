Output finos-calm-airlock-demo.mp4
Output finos-calm-airlock-demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1440
Set Height 820
Set Padding 28
Set Margin 14
Set MarginFill "#0f111a"
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "TokyoNight"
Set TypingSpeed 45ms

Hide
Type 'export PS1="\[\033[1;36m\]cmdrvl@finos-demo\[\033[0m\] $ "'
Enter
Type "clear"
Enter
Sleep 400ms
Show

Type "# FINOS CALM AIR-OP-028 + AIGF MI-20: From Static Spec to Cryptographic Wire Proof"
Enter
Sleep 2.5s

Type "./run_demo.py 1"
Enter
Sleep 7s

Type "./run_demo.py 2"
Enter
Sleep 8s

Type "clear"
Enter
Sleep 500ms

Type "# Live egress proxy: no base64 regex in policy — recursive boundary-detectors"
Enter
Sleep 2s

Type "./run_demo.py 3"
Enter
Sleep 9.5s

Type "./run_demo.py 4"
Enter
Sleep 6.5s

Type "jq '.evidence' out/evidence.json"
Enter
Sleep 7.5s

Type "clear"
Enter
Sleep 500ms

Type "# Offline auditor verification (zero network, zero accounts) + 1-byte tamper test"
Enter
Sleep 2s

Type "./run_demo.py 5"
Enter
Sleep 11s
