#!/bin/bash
# -----------------------------------------------------------------------------
# Translation Update Script
# -----------------------------------------------------------------------------
cd "$(dirname "$0")/.."

LANG_CODE=${1:-nl}
BASE_DIR="src/check_truststore"
POT_FILE="${BASE_DIR}/locale/check_truststore.pot"
PO_DIR="${BASE_DIR}/locale/${LANG_CODE}/LC_MESSAGES"
PO_FILE="${PO_DIR}/check_truststore.po"
MO_FILE="${PO_DIR}/check_truststore.mo"

echo "Updating translations for: ${LANG_CODE}..."

find "$BASE_DIR" -name "*.py" | xgettext -L Python --from-code=UTF-8 \
    --keyword=_ \
    -o "$POT_FILE" -f -

mkdir -p "$PO_DIR"

if [ ! -f "$PO_FILE" ]; then
    echo "Creating new .po file for ${LANG_CODE}..."
    msginit -i "$POT_FILE" -o "$PO_FILE" -l "$LANG_CODE" --no-translator
else
    msgmerge --quiet -U "$PO_FILE" "$POT_FILE"
fi

msgfmt "$PO_FILE" -o "$MO_FILE"

echo "Done! Compiled: ${MO_FILE}"