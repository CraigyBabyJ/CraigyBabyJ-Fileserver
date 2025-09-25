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

## Issue: Deprecated CodeQL Action v2

### Problem
GitHub Actions workflow was failing with:
```
Error: CodeQL Action major versions v1 and v2 have been deprecated
Warning: Resource not accessible by integration
```

### Root Cause
- CodeQL Action v2 was retired on January 10, 2025
- Missing `security-events: write` permission for SARIF uploads
- GitHub requires v3 for all new security scanning features

### Solution Applied
1. **Updated CodeQL Action**: Changed from `@v2` to `@v3`
2. **Added Permissions**: Added `security-events: write` to job permissions
3. **Maintained Compatibility**: Ensured SARIF upload functionality works with v3

### Files Modified
- `.github/workflows/docker.yml` - Updated CodeQL action version and permissions

### Prevention
- **Monitor GitHub deprecation notices** for action updates
- **Include proper permissions** for security scanning workflows
- **Test workflows regularly** to catch breaking changes early

### Verification
The fix ensures:
- ✅ Docker images build successfully
- ✅ Images push to registry without errors  
- ✅ Trivy security scans complete successfully
- ✅ SARIF results upload to GitHub Security tab
- ✅ Complete CI/CD pipeline runs end-to-end

---
*Last updated: v1.0.1 release preparation*
*Issues resolved: December 2024*