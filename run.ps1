Write-Host "Starting SecureShare API and Frontend..."

# Get current path
$baseDir = Get-Location

# Start Backend using Python module runner for maximum reliability
Start-Process powershell -ArgumentList "-NoExit -Command `"cd '$baseDir'; .\venv\Scripts\python.exe -m uvicorn backend.main:app --reload`""

# Start Frontend using Python module runner
Start-Process powershell -ArgumentList "-NoExit -Command `"cd '$baseDir'; .\venv\Scripts\python.exe -m streamlit run frontend\app.py`""

Write-Host "Applications launched in new windows."
