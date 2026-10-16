# Hotfix deploy

1. `git pull --ff-only origin release`
2. `kubectl set image deployment/api api=registry.example.com/api:$TAG`
3. `kubectl rollout status deployment/api --timeout=5m`
