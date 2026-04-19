#!/bin/bash

#!/bin/bash

# Gebruik de opgegeven taal of standaard 'nl'
LANG_CODE=${1:-nl}
POT_FILE="locale/check_truststore.pot"
PO_DIR="locale/${LANG_CODE}/LC_MESSAGES"
PO_FILE="${PO_DIR}/check_truststore.po"
MO_FILE="${PO_DIR}/check_truststore.mo"

echo "Updating translations for: ${LANG_CODE}..."
xgettext -L Python --from-code=UTF-8 -o "$POT_FILE" check_truststore

mkdir -p "$PO_DIR"

if [ ! -f "$PO_FILE" ]; then
    echo "Creating new .po file for ${LANG_CODE}..."
    msginit -i "$POT_FILE" -o "$PO_FILE" -l "$LANG_CODE" --no-translator
else
    msgmerge --quiet -U "$PO_FILE" "$POT_FILE"
fi

msgfmt "$PO_FILE" -o "$MO_FILE"

echo "Done! Compiled: ${MO_FILE}"
