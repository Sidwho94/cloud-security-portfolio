# PowerShell script to test Kyverno policy enforcement
Write-Host "[*] Applying Kyverno ClusterPolicies..." -ForegroundColor Cyan
kubectl apply -f ../kyverno-policies/

Write-Host "`n[*] Testing Admission Control with INSECURE pod (Expected to FAIL)..." -ForegroundColor Yellow
$result = kubectl apply -f ../manifests/insecure-pod.yaml 2>&1
Write-Host $result

if ($LASTEXITCODE -ne 0) {
    Write-Host "[+] SUCCESS: Insecure Pod was successfully BLOCKED by Kyverno!" -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: Insecure Pod was allowed! Check policy configuration." -ForegroundColor Red
}

Write-Host "`n[*] Testing Admission Control with HARDENED pod (Expected to PASS)..." -ForegroundColor Cyan
kubectl apply -f ../manifests/hardened-pod.yaml

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] SUCCESS: Compliant Hardened Pod was successfully ADMITTED!" -ForegroundColor Green
    kubectl delete -f ../manifests/hardened-pod.yaml
} else {
    Write-Host "[-] ERROR: Hardened pod was rejected unexpectedly." -ForegroundColor Red
}
