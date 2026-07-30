# This file ensures the data directory is tracked in git
@"
# This directory contains the database file
# db.json will be created automatically when the server starts
"@ | Out-File -FilePath data\.gitkeep -Encoding utf8