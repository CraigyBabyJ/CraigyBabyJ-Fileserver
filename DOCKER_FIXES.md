# Docker CI/CD Fixes Documentation

## Issue: Container Registry Case Sensitivity

### Problem
GitHub Actions workflow was failing during Trivy security scans with the error:
```
FATAL failed to parse the image name: ghcr.io/CraigyBabyJ/craigybabyj-fileserver:latest
```

### Root Cause
- `${{ github.repository_owner }}` returns `CraigyBabyJ` (mixed case)
- Container registries (ghcr.io, Docker Hub) require **all lowercase** names
- This created invalid image references like: `ghcr.io/CraigyBabyJ/craigybabyj-fileserver:latest`

### Solution Applied
1. **IMAGE_NAME variable**: Set to `${{ github.repository_owner }}/craigybabyj-fileserver` (works for build/push)
2. **Trivy scan**: Hardcoded to `ghcr.io/craigybabyj/craigybabyj-fileserver:latest` (prevents parsing errors)

### Files Modified
- `.github/workflows/docker.yml` - Added comments and hardcoded image reference for Trivy scan

### Prevention
- **Always use lowercase** for container image names
- **Test with actual repository owner names** that may contain uppercase letters
- **Document case sensitivity requirements** in CI/CD configurations

### Verification
The fix ensures:
- ✅ Docker images build successfully
- ✅ Images push to registry without errors  
- ✅ Trivy security scans complete successfully
- ✅ Complete CI/CD pipeline runs end-to-end

---
*Last updated: v1.0.1 release preparation*
*Issue resolved: December 2024*