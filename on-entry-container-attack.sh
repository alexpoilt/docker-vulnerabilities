#!/bin/bash
# Amanda Souza Version: 1.0
# This script was adapted of RedHat code to check docker vulnerabilities in Ubuntu 
# Even more detailed explanation is located at https://access.redhat.com/security/vulnerabilities/cve-2016-9962

RED="\033[1;31m"
YELLOW="\033[1;33m"
GREEN="\033[1;32m"
BOLD="\033[1m"
RESET="\033[0m"

UPSTREAM_FIX="1.12.6"
LAST_VULNERABLE_RHEL_DOCKER="1.12.5-9"
LAST_VULNERABLE_RHEL_DOCKER_LATEST="1.12.5-9"



compare4() {
    local left=( $( tr ".-" "  " <<< "$1" ) )
    local right=( $( tr ".-" "  " <<< "$3" ) )
    local expression="$2"

    if [[ "$expression" == *"="* ]]; then
        if (( left[0] == right[0] && 
              left[1] == right[1] && 
              left[2] == right[2] && 
              left[3] == right[3] )); then
            return 0
        fi
    fi

    if [[ "$expression" == *">"* ]]; then
        if (( left[0] > right[0] ||
              left[0] == right[0] && left[1] > right[1] ||
              left[0] == right[0] && left[1] == right[1] && left[2] > right[2] ||
              left[0] == right[0] && left[1] == right[1] && left[2] == right[2] && left[3] > right[3] )); then
            return 0
        fi
    fi
    
    if [[ "$expression" == *"<"* ]]; then
        if (( left[0] < right[0] ||
              left[0] == right[0] && left[1] < right[1] ||
              left[0] == right[0] && left[1] == right[1] && left[2] < right[2] ||
              left[0] == right[0] && left[1] == right[1] && left[2] == right[2] && left[3] < right[3] )); then
            return 0
        fi
    fi
    
    return 1
}

# Help and parameters
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  echo "Usage: $( basename "$0" ) [--no-colors]"
  exit 1
fi
if [[ "$1" == "--no-colors"  ]]; then
    RED=""
    YELLOW=""
    GREEN=""
    BOLD=""
    RESET=""
fi

# Desclimer
echo
echo -e "${BOLD}This script is primarily designed to detect On-entry Container Attack"
echo

# Parse docker version
for package in $( dpkg -l | grep docker ); then
	version=$( echo "$package" | awk '{ print $3}' )
	if [[ "$version" =~ $DOCKER_PATTERN ]]; then
        	docker_package_name=$( echo "$package" | awk '{ print $2}' )
        	docker_version=$( echo "$package" | sed 's/^\(.*\)~.*$/\1/' )
		check_vulnerability
	fi
done

# Check docker even installed
if [[ ! "$docker_package_name" ]]; then
    echo -e "'docker' was not detected on your system."
    exit 0
fi

# Print results
return_value=()

check_vulnerability(){
	echo -e "Detected package '$BOLD$docker_package_name$RESET'."
	echo
        if compare4 "$docker_version" "<=" "$LAST_VULNERABLE_RHEL_DOCKER"; then
                echo -e "${RED}This package is vulnerable, because it is older or the same as the last built vulnerable version $LAST_VULNERABLE_RHEL_DOCKER.${RESET}"
                echo -e "${RED}SELinux would mitigate the issue, but it is disabled.${RESET}"
                echo -e "${YELLOW}Update 'docker' to version older than ${RESET}$UPSTREAM_FIX ${YELLOW}version.${RESET}"
                return_value+=(3)
        else
            echo -e "${GREEN}This package is safe, because it is newer than last built vulnerable version ${YELLOW}$LAST_VULNERABLE_RHEL_DOCKER.${RESET}"
            return_value+=(0)
        fi
	echo 
fi
}

# Return value
max=0
for v in "${return_value[@]}"; do
    if (( v > max )); then 
        max=$v
    fi 
done
exit "$max"
