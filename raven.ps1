$ErrorActionPreference = "Stop"
$env:PYTHONIOENCODING = "utf-8"
& "$PSScriptRoot\venv\Scripts\python.exe" "$PSScriptRoot\raven.py" $args
