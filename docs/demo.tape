# VHS tape for the Seshat terminal demo (https://github.com/charmbracelet/vhs)
# Produce the GIF with:  vhs docs/demo.tape
# (Outputs docs/demo.gif — prefer this over the committed animated SVG when VHS
#  is available; it's the house standard.)

Output docs/demo.gif

Set FontSize 18
Set Width 1100
Set Height 640
Set Theme "Dracula"
Set Padding 18

Type "pipx install seshat-scanner"
Enter
Sleep 800ms

Type "seshat ingest ./MyVault.sol"
Enter
Sleep 1s

Type "seshat scan"
Enter
Sleep 1500ms

Type "seshat report"
Enter
Sleep 3s
