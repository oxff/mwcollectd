#!/bin/bash

# any file older than this will be removed
# the filename pattern configured in filestore-streams.conf
# overwritten by argv[1]
LOG_FILENAME="/opt/mwcollectd/var/log/mwcollectd/streams-%HOUR%.log"
# set this to "NEVER" to disable deletion
# overwritten by argv[2]
DELETE_TIME="1 week ago"
# comment or remove the following line to make the script work
CONFIGURED="no"
# -- NO CONFIGURATION BELOW THIS LINE -- #

if [[ "$#" -eq 0 ]] && [[ "$CONFIGURED" = "no" ]]; then
	echo "ERROR: No configuration in script and no parameters, exiting!" >&2
	echo "Usage: $(basename "$0") [log-pattern [deletion-date-pattern]]" >&2
	echo "e.g. $(basename "$0") '$LOG_FILENAME' '$DELETE_TIME'" >&2
	exit 0
fi

if [[ "$#" -ge 1 ]]; then
	LOG_FILENAME="$1"
elif [[ "$#" -eq 2 ]]; then
	DELETE_TIME="$2"
fi

if echo "$LOG_FILENAME" | egrep -q "[\*\?]|\{.*,.*\}|\[.*\]"; then
	echo "ERROR: \"$LOG_FILENAME\" contains glob wildcards, aborting for safety" >&2
	exit 0
fi

if ! date -d "$DELETE_TIME" 2> /dev/null; then
	echo "ERROR: \"$DELETE_TIME\" is not understood correctly" >&2
	exit 0
fi

shopt -s nullglob

LOG_NOW=$(echo "$LOG_FILENAME" | sed "s/%HOUR%/$(date '+%Y%m%d-%H%z')/" )
LOG_DELETE="$(echo "$LOG_FILENAME" | sed "s/%HOUR%/$(date '+%Y%m%d-%H%z' -d "$DELETE_TIME")/" ).gz"
LOG_MASK=$(echo "$LOG_FILENAME" | sed 's/%HOUR%/*/')
LOG_FILES=($LOG_MASK)
LOG_MASK_GZ="${LOG_MASK}.gz"
LOG_FILES_GZ=($LOG_MASK_GZ)

# compress files older than the current one
for file in "${LOG_FILES[@]}"; do
	if [[ "$file" < "$LOG_NOW" ]]; then
		gzip -f -n -q --best $file
	fi
done

# delete old compressed files
if [[ "$DELETE_TIME" != "NEVER" ]]; then
	for file in "${LOG_FILES_GZ[@]}"; do
		if [[ "$file" < "$LOG_DELETE" ]]; then
			rm -f "$file"
		fi
	done
fi
