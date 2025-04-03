Write-Host "[1/4] Creo ambiente virtuale..."
python -m venv venv

Write-Host "[2/4] Attivo ambiente virtuale..."
. .\venv\Scripts\Activate.ps1

Write-Host "[3/4] Installo i pacchetti necessari..."
pip install psutil pandas matplotlib numpy

Write-Host "[4/4] Ambiente pronto! Per riattivarlo in futuro:"
Write-Host 'Esegui: `. .\venv\Scripts\Activate.ps1`'
