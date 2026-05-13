#!/bin/bash
# -----------------------------------------------------------------------------
# Translation Update Script
# -----------------------------------------------------------------------------
cd "$(dirname "$0")/.."

BASE_DIR="src/check_truststore"
LOCALE_DIR="${BASE_DIR}/locale"
POT_FILE="${LOCALE_DIR}/check_truststore.pot"
PYPROJECT="pyproject.toml"

if [ -f "$PYPROJECT" ]; then
    VERSION=$(grep -m 1 '^version = ' "$PYPROJECT" | cut -d '"' -f 2)
    echo "[*] Detected version: ${VERSION}"
else
    VERSION="unknown"
    echo "[-] Warning: pyproject.toml not found."
fi

echo "[*] Extracting messages from source..."
find "$BASE_DIR" -name "*.py" | xgettext -L Python --from-code=UTF-8 \
    --keyword=_ \
    --keyword=N_ \
    --no-location \
    --package-name="check_truststore" \
    --package-version="${VERSION}" \
    -o "$POT_FILE" -f -

if [ -n "$1" ]; then
    LANGUAGES=("$1")
else
    LANGUAGES=($(find "$LOCALE_DIR" -maxdepth 1 -mindepth 1 -type d -exec basename {} \;))
fi

for LANG_CODE in "${LANGUAGES[@]}"; do
    [ "$LANG_CODE" == "LC_MESSAGES" ] && continue

    PO_DIR="${LOCALE_DIR}/${LANG_CODE}/LC_MESSAGES"
    PO_FILE="${PO_DIR}/check_truststore.po"
    MO_FILE="${PO_DIR}/check_truststore.mo"

    echo "--- Updating language: ${LANG_CODE} ---"
    mkdir -p "$PO_DIR"

    if [ ! -f "$PO_FILE" ]; then
        echo "Creating new .po file for ${LANG_CODE}..."
        msginit --no-location -i "$POT_FILE" -o "$PO_FILE" -l "$LANG_CODE" --no-translator
    else
        msgmerge --quiet -U "$PO_FILE" "$POT_FILE"
        sed -i "s/^\"Project-Id-Version: .*/\"Project-Id-Version: check_truststore ${VERSION}\\\\n\"/" "$PO_FILE"
    fi

    echo "[*] Compiling to .mo..."
    msgfmt "$PO_FILE" -o "$MO_FILE"
done

echo -e "\n\033[1;32m[#] All translations are up-to-date!\033[0m"