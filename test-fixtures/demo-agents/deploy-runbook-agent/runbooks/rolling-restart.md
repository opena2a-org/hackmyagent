# Rolling restart

1. `kubectl get pods -l app=$SERVICE`
2. `kubectl rollout restart deployment/$SERVICE`
3. `kubectl rollout status deployment/$SERVICE --timeout=10m`
4. Post the rollout status to the incident channel.
