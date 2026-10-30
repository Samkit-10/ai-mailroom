# Move the Dockerfile out of the docker directory into the root
git mv docker/Dockerfile ./

# Remove the now-empty docker directory
rmdir docker 2>/dev/null || rm -rf docker

# Commit and push the structural update to GitHub
git add Dockerfile
git commit -m "Move Dockerfile to root directory"
git push origin main
