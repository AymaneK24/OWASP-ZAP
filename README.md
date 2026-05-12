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


kubectl apply -f K8S/internet/gatewayclass.yaml
kubectl get gatewayclass -n envoy-gateway-system
kubectl apply -f K8S/internet/gateway.yaml
kubectl get gateway -n jesa -w
Ctrl+C
```
dns record to jesa.aymanekenbouch.online in Azure DNS Zone


```
kubectl create secret generic backend-secret --namespace jesa `
  --from-literal=ENTRA_TENANT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX `
  --from-literal=ENTRA_CLIENT_ID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX `
  --from-literal=ENTRA_CLIENT_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX `
  --from-literal=SESSION_SECRET=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX `

kubectl apply -f K8S/internet/clusterissuer.yaml
kubectl get clusterissuer -n jesa
kubectl apply -f K8S/internet/certificate.yaml
kubectl get certificate -n jesa -w 
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

## DAST Scans

L'entreprise utilise deja les client secrets stocké dans variable groupes pour le deploiment des applications sur backends et la configuration d'authenification  lors du runtime à travers les variables groupe a travers les K8S Secrets



l'architecture de la solution est basé sur l'utilisation de ces secrets Client secrets pour faire l'extraction du token a travers bach script et l'injection de ce Token (Bearer Access Token )dans l'operation de scan ,  ce qui garantie un scan authentifé. 
![alt text](./images/ARCHDAST.png)


pour La discovery des endpoints du backend: 
La version docker de OWASP ZAP ne peut pas trouvé tous les endpoints du backend et front les plus critiques.

Solution: 

- Quelque projet utilise swagger pour la collection des endpoint du backend et les exposer  à travers /swagger.json

![alt](./images/image.png)

donc ils serait facile de faire discovery car ils sont déja pris à l'aide de Automation framework d'OWASP ZAP.

sinon ils faut definir explicitement les endpoints su backend 
- /api/dashboard 
- /api/health 
.... explicitment





## SAST Scans

This solution displays security issues and detect secrets, the solution is based on two opesource tools:
opengrep for it's security focused issue detection
gitleaks for it's power to detect secrets

![|200](./images/opengrep.png)
![|100](./images/gitleaks.png)

un scan dans le pipline du code fetché et le resultat des rapport SARFI , ils seront tranfer vers fichier json et puis 



