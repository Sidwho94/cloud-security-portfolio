# PowerShell script to create a local Kind cluster and install Kyverno ($0 Cost)
Write-Host "[*] Creating local Kind cluster 'k8s-sec-lab'..." -ForegroundColor Cyan
kind create cluster --name k8s-sec-lab

Write-Host "[*] Installing Kyverno Admission Controller via Helm / Manifests..." -ForegroundColor Cyan
kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.12.0/install.yaml

Write-Host "[*] Waiting for Kyverno Admission Controller pods to become Ready..." -ForegroundColor Cyan
kubectl wait --namespace kyverno --for=condition=ready pod --selector=app.kubernetes.io/part-of=kyverno --timeout=120s

Write-Host "[+] Local Kubernetes Security Lab is Ready!" -ForegroundColor Green
