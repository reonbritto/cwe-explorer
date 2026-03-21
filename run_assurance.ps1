Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PureSecure - CVE Details QA Pipeline" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Security analysis with Bandit
Write-Host "[1/3] Running Bandit for security analysis..." -ForegroundColor Yellow
.\venv\Scripts\bandit.exe -r app\ -ll
Write-Host ""

# Step 2: Code style check with Flake8
Write-Host "[2/3] Running Flake8 for linting..." -ForegroundColor Yellow
.\venv\Scripts\flake8.exe app\ tests\ --max-line-length=100
Write-Host ""

# Step 3: Automated tests with Pytest
Write-Host "[3/3] Running Pytest for automated testing..." -ForegroundColor Yellow
.\venv\Scripts\pytest.exe tests\ -v
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "  QA Pipeline Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
