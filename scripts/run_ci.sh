#!/bin/bash
set -e

cleanup() {
    echo -e "\n\033[1;36m[#] Cleaning up bytecode and temporary files...\033[0m"
    find src -name "__pycache__" -type d -exec rm -rf {} +
    rm -rf src/*.egg-info
}

trap cleanup EXIT

cd "$(dirname "$0")/.."

PYTHON_VERSIONS=("3.7" "3.9" "3.14")
REFERENCE_VER="3.14"
STORES_YAML="vars/tst/stores.yml"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

echo "--- Fedora/Podman CI for check_truststore v1.1.0 ---"

echo "[*] Compiling translations..."
find src/check_truststore/locale -name "*.po" -exec msgfmt {} -o {}s/po/mo/ \; 2>/dev/null || echo "Warning: msgfmt not found, skipping compilation."

for PY_VER in "${PYTHON_VERSIONS[@]}"; do
    echo -e "\n\033[1;34m>>> Testing Python ${PY_VER} [Full Test]\033[0m"

    # Gebruik PIP_ROOT_USER_ACTION environment variabele voor maximale stilte
    # En --no-input om interactie te voorkomen
    podman run --rm \
        -v ".:/app:Z" \
        -w /app \
        -e PIP_ROOT_USER_ACTION=ignore \
        python:${PY_VER}-slim \
        /bin/bash -c "
            python3 -m pip install --quiet --no-cache-dir --upgrade pip && \
            python3 -m pip install --quiet --no-cache-dir -e '.[all]' && \
            chmod +x check_truststore && \

            # 1. JSON output
            ./check_truststore $STORES_YAML -f json > $LOG_DIR/output_${PY_VER}.json 2> $LOG_DIR/error_${PY_VER}.log && \
            
            # 2. TEXT output
            ./check_truststore $STORES_YAML -f text -d > $LOG_DIR/output_${PY_VER}.txt 2>> $LOG_DIR/error_${PY_VER}.log && \
            
            # 3. STATUS output
            ./check_truststore $STORES_YAML -f status > $LOG_DIR/status_${PY_VER}.json 2>> $LOG_DIR/error_${PY_VER}.log; \
            RET=\$?; \
            if [ \$RET -le 5 ]; then \
                echo 'Status check completed with code '\$RET; \
            else \
                echo 'Status check failed with fatal code '\$RET; exit \$RET; \
            fi && \
            
            echo 'Success: All formats and stderr logged for ${PY_VER}'
        "
done

echo -e "\n\033[1;33m>>> Testing Python 3.6 [Minimal - No Pydantic]\033[0m"

podman run --rm \
    -v ".:/app:Z" \
    -w /app \
    -e PIP_ROOT_USER_ACTION=ignore \
    python:3.6-slim \
    /bin/bash -c "
        python3 -m pip install --quiet --no-cache-dir 'pip<22.0' && \
        python3 -m pip install --quiet --no-cache-dir cryptography PyYAML && \
        chmod +x check_truststore && \
        
        echo '1. JSON Minimal...' && \
        ./check_truststore $STORES_YAML -f json > $LOG_DIR/output_no_pydantic.json 2> $LOG_DIR/error_no_pydantic.log && \
        
        echo '2. TEXT Minimal...' && \
        ./check_truststore $STORES_YAML -f text -d > $LOG_DIR/output_no_pydantic.txt 2>> $LOG_DIR/error_no_pydantic.log && \
        
        echo '3. STATUS Minimal...' && \
        ./check_truststore $STORES_YAML -f status > $LOG_DIR/status_no_pydantic.json 2>> $LOG_DIR/error_no_pydantic.log; \
        RET=\$?; \
        echo 'Fallback exit code: '\$RET; \
        
        if [ -f \"$LOG_DIR/status_no_pydantic.json\" ]; then
            echo 'Success: All fallback logs generated';
        else
            echo \"Error: $LOG_DIR/status_no_pydantic.json missing!\"; exit 1;
        fi
    "

echo -e "\n\033[1;32m--- All container runs completed! ---\033[0m"

echo -e "\n\033[1;35m--- Quality Control (Audit) ---\033[0m"

REFERENCE_JSON="$LOG_DIR/output_${REFERENCE_VER}.json"
REFERENCE_STATUS="$LOG_DIR/status_${REFERENCE_VER}.json"
CHECK_LIST=("${PYTHON_VERSIONS[@]}" "no_pydantic")

for VER in "${CHECK_LIST[@]}"; do
    for FILE_TYPE in "output" "status"; do
        TARGET="$LOG_DIR/${FILE_TYPE}_${VER}.json"
        
        if [ ! -s "$TARGET" ]; then
            echo -e "❌ ERROR: $TARGET is EMPTY or missing!"
            exit 1
        fi

        if ! python3 -c "import json; json.load(open('$TARGET'))" 2>/dev/null; then
            echo -e "❌ ERROR: $TARGET contains invalid JSON!"
            exit 1
        fi
    done
    echo -e "✅ $VER: All JSON files present and valid."
done

if grep -q "exitCode" "$REFERENCE_STATUS" && grep -q "groupName" "$REFERENCE_JSON"; then
    echo -e "✅ Field-check: 'exitCode' and 'groupName' are correctly present."
else
    echo -e "❌ Field-check: Essential fields missing in reference files!"
    exit 1
fi

echo -e "\n\033[1;35m--- Consistency Check (vs ${REFERENCE_VER}) ---\033[0m"

for VER in "${CHECK_LIST[@]}"; do
    if [ "$VER" == "$REFERENCE_VER" ]; then continue; fi
    
    if diff "$REFERENCE_JSON" "$LOG_DIR/output_${VER}.json" > /dev/null; then
        echo -e "✅ Data:   ${REFERENCE_VER} vs $VER is identical."
    else
        echo -e "⚠️ Data:   Differences found in output_${VER}.json!"
    fi

    if diff -I '"scanDate":' "$REFERENCE_STATUS" "$LOG_DIR/status_${VER}.json" > /dev/null; then
        echo -e "✅ Status: ${REFERENCE_VER} vs $VER is identical (timestamps ignored)."
    else
        echo -e "⚠️ Status: Content differences found in status_${VER}.json!"
        diff -u -I '"scanDate":' "$REFERENCE_STATUS" "$LOG_DIR/status_${VER}.json" | head -n 10
    fi
done

echo -e "\n\033[1;33m[*] Final validation results (based on ${REFERENCE_VER})...\033[0m"

EXIT_VAL=$(python3 -c "import json; print(json.load(open('$REFERENCE_STATUS'))['metadata']['exitCode'])")

if [ "$EXIT_VAL" -eq 7 ]; then
    echo -e "  ❌ FATAL: Renderer crashed (Code 7)."
    exit 1
elif [ "$EXIT_VAL" -eq 4 ]; then
    echo -e "  ✅ Validation: Certificate errors found (Code 4), as expected."
else
    echo -e "  ✅ Validation: Status code $EXIT_VAL received."
fi

echo -e "\n\033[1;32m--- CI SUCCEEDED ---\033[0m"