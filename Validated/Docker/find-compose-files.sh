#!/bin/bash

echo "Scanning running containers for Docker Compose usage..."

# Get all running container IDs
containers=$(docker ps -q)

if [ -z "$containers" ]; then
    echo "No running containers found."
    exit 0
fi

for container in $containers; do
    # Get container name
    cname=$(docker inspect -f '{{ .Name }}' "$container" | sed 's|/||')
    
    # Try to get the Docker Compose project label
    project=$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$container" 2>/dev/null)

    if [ -n "$project" ]; then
        echo "[$cname] is part of Docker Compose project: '$project'"

        # Try to locate the docker-compose.yml file for that project
        echo "Searching for docker-compose.yml for project '$project'..."
        matches=$(find / -type f -name 'docker-compose.yml' -path "*/$project/*" 2>/dev/null)

        if [ -n "$matches" ]; then
            echo "  ➤ Possible docker-compose.yml locations:"
            echo "$matches" | sed 's/^/    - /'
        else
            echo "  ⚠ No compose file found on disk matching project '$project'"
        fi
    else
        echo "[$cname] does NOT appear to be managed by Docker Compose."
    fi

    echo
done

