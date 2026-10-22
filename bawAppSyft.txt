#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 twx component version" >&2

    exit 1
fi

INPUT_FILE="$1"
EXTRACTED_DIR="extracted"
TOOLKITS_DIR="$EXTRACTED_DIR/toolkits"
SCANNING_DIR="syft"
MAIN_PACKAGE_XML="$EXTRACTED_DIR/META-INF/package.xml"
COMPONENT="$2"
VERSION="$3"

find_object_index() {
    local SEARCH_ID="$1"
    local i

    for (( i=0; i<${#OBJECT_IDS[@]}; i++ )); do
        if [[ "${OBJECT_IDS[$i]}" == "$SEARCH_ID" ]]; then
            echo "$i"

            return 0
        fi
    done

    echo "-1"

    return 1
}

parse_jar_objects() {
    local XML_FILE="$1"
    local EX_DIR="$2"
    local LINE OBJECT_ID OBJECT_NAME FILE_ID FILE_PATH

    local -a OBJECT_IDS=()
    local -a OBJECT_NAMES=()

    if [[ ! -f "$XML_FILE" ]]; then
        echo "ERROR: File not found: $XML_FILE" >&2

        return 1
    fi

    while IFS= read -r LINE; do
        if [[ "$LINE" == *"<object "* ]]; then
            OBJECT_ID=$(printf '%s\n' "$LINE" | sed -nE 's/.*id="([^"]*)".*/\1/p')
            OBJECT_NAME=$(printf '%s\n' "$LINE" | sed -nE 's/.*name="([^"]*)".*/\1/p')
            OBJECT_TYPE=$(printf '%s\n' "$LINE" | sed -nE 's/.*type="([^"]*)".*/\1/p')

            if [[ "$OBJECT_NAME" == *.jar && "$OBJECT_TYPE" == "managedAsset" ]]; then
                OBJECT_IDS+=("$OBJECT_ID")
                OBJECT_NAMES+=("$OBJECT_NAME")
            fi
        fi

        if [[ "$LINE" == *"<file "* ]]; then
            FILE_ID=$(printf '%s\n' "$LINE" | sed -nE 's/.*id="([^"]*)".*/\1/p')
            FILE_PATH=$(printf '%s\n' "$LINE" | sed -nE 's/.*path="([^"]*)".*/\1/p')

            if [[ " ${OBJECT_IDS[*]} " == *" $FILE_ID "* ]]; then
                NAME_INDEX=$(find_object_index "$FILE_ID")

                cp "$EX_DIR/files/$FILE_ID/$FILE_PATH" "$SCANNING_DIR/${OBJECT_NAMES[$NAME_INDEX]}"
            fi
        fi
    done < "$XML_FILE"
}

mkdir -p "$EXTRACTED_DIR"
mkdir -p "$SCANNING_DIR"

unzip -o "$INPUT_FILE" -d "$EXTRACTED_DIR" > /dev/null

parse_jar_objects "$MAIN_PACKAGE_XML" "$EXTRACTED_DIR"

find "$TOOLKITS_DIR" -type f -iname '*.zip' -print0 |
while IFS= read -r -d '' TOOLKIT_FILE; do
    DEST_TOOLKIT="${TOOLKIT_FILE}.extracted"

    mkdir -p "$DEST_TOOLKIT"

    unzip -o "$TOOLKIT_FILE" -d "$DEST_TOOLKIT"  > /dev/null

    TOOLKIT_PACKAGE_XML="$DEST_TOOLKIT/META-INF/package.xml"

    parse_jar_objects "$TOOLKIT_PACKAGE_XML" "$DEST_TOOLKIT"
done

syft scan $SCANNING_DIR -o cyclonedx-json@1.6=sbom.json --select-catalogers java --source-name "$COMPONENT" --source-version "$VERSION"

rm -r $EXTRACTED_DIR
rm -r $SCANNING_DIR
