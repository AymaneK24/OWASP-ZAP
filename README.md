```
helm install eg oci://docker.io/envoyproxy/gateway-helm --version v0.0.0-latest -n envoy-gateway-system --create-namespace
kubectl wait --timeout=5m -n envoy-gateway-system deployment/envoy-gateway --for=condition=Available

helm repo update

helm upgrade --install cert-manager jetstack/cert-manager `
  --namespace cert-manager `
  --create-namespace `
  --set crds.enabled=true `
  --set "extraArgs={--enable-gateway-api}"

kubectl create namespace jesa


kubectl apply -f gatewayclass.yaml
kubectl apply -f gateway.yaml
```
dns record to jesa.aymanekenbouch.online in Azure DNS Zone


```
kubectl apply -f K8S/internet/clusterissuer.yaml
kubectl apply -f K8S/internet/certificate.yaml
kubectl apply -f K8S/internet/httproute.yaml
kubectl get certificate -n jesa -w
```

App deployment
```
kubectl apply -f K8S/internet/backend.yaml
kubectl apply -f K8S/internet/backend-service.yaml
kubectl apply -f K8S/internet/frontend.yaml
kubectl apply -f K8S/internet/frontend-service.yaml
kubectl get pods -n jesa
```
Everything is good!



## DAST

