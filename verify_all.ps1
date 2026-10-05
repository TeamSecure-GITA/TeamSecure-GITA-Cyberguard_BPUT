$ErrorActionPreference = 'Continue'
$script:results = @()
$root = $PSScriptRoot

function Invoke-VerificationStep {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    try {
        $global:LASTEXITCODE = 0
        & $Action
        if ($LASTEXITCODE -ne 0) {
            throw "Command exited with code $LASTEXITCODE"
        }
        $script:results += "PASS  $Name"
    }
    catch {
        $script:results += "FAIL  ${Name}: $_"
    }
}

Invoke-VerificationStep 'Backend test suite' {
    Push-Location (Join-Path $root 'cyberguard-backend')
    try { python -m pytest -q } finally { Pop-Location }
}

Invoke-VerificationStep 'Frontend lint' {
    Push-Location (Join-Path $root 'cyberguard-frontend')
    try { npm.cmd run lint } finally { Pop-Location }
}

Invoke-VerificationStep 'Frontend production build' {
    Push-Location (Join-Path $root 'cyberguard-frontend')
    try { npm.cmd run build } finally { Pop-Location }
}

Invoke-VerificationStep 'Render YAML and AI runtime config' {
    Push-Location $root
    try {
        python -c "import yaml; data=yaml.safe_load(open('render.yaml', encoding='utf-8')); service=data['services'][0]; env={item['key']:item.get('value') for item in service['envVars']}; assert 'requirements-models.txt' in service['buildCommand']; assert env['CYBERGUARD_ENABLE_PRETRAINED_MEDIA']=='true'; assert env['CYBERGUARD_ENABLE_RDAP']=='true'"
    } finally { Pop-Location }
}

Invoke-VerificationStep 'Python dependency consistency' {
    python -m pip check
}

Invoke-VerificationStep 'Pretrained image/audio model inference' {
    Push-Location (Join-Path $root 'cyberguard-backend')
    try { python check_models.py } finally { Pop-Location }
}

if ($env:API_URL) {
    Invoke-VerificationStep 'Deployed API health' {
        $response = Invoke-RestMethod -Uri "$($env:API_URL.TrimEnd('/'))/" -TimeoutSec 15
        if ($response.status -ne 'Active') { throw 'API root endpoint did not report Active.' }
    }
}
else {
    $script:results += 'SKIP  Deployed API health (set API_URL to enable)'
}

if ($env:CYBERGUARD_FRONTEND_URL) {
    Invoke-VerificationStep 'Playwright frontend smoke test' {
        Push-Location (Join-Path $root 'cyberguard-frontend')
        try { npm.cmd run test:smoke } finally { Pop-Location }
    }
}
else {
    $script:results += 'SKIP  Playwright frontend smoke test (set CYBERGUARD_FRONTEND_URL to enable)'
}

$reportPath = Join-Path $root 'release-report.txt'
$script:results | Tee-Object -FilePath $reportPath
if ($script:results -match '^FAIL') { exit 1 }
exit 0