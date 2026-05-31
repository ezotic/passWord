#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
ENV_FILE="$SCRIPT_DIR/.env"

[[ -f "$ENV_FILE" ]] && { set -a; source "$ENV_FILE"; set +a; }

TARGET_USER="${1:-admin}"

validate_password() {
    local p="$1"
    local len="${#p}"
    if [[ $len -lt 12 || $len -gt 20 ]]; then
        echo "  Password must be 12–20 characters (got $len)" >&2; return 1
    fi
    [[ "$p" =~ [a-z] ]] || { echo "  Must contain a lowercase letter" >&2; return 1; }
    [[ "$p" =~ [A-Z] ]] || { echo "  Must contain an uppercase letter" >&2; return 1; }
    [[ "$p" =~ [0-9] ]] || { echo "  Must contain a number" >&2; return 1; }
    [[ "$p" =~ [^a-zA-Z0-9] ]] || { echo "  Must contain a special character" >&2; return 1; }
}

echo "=== Admin Password Reset ==="
echo "Target user: $TARGET_USER"
echo

while true; do
    read -r -s -p "New password: " NEW_PASS; echo
    read -r -s -p "Confirm password: " CONFIRM; echo

    if [[ "$NEW_PASS" != "$CONFIRM" ]]; then
        echo "Passwords do not match. Try again." >&2
        continue
    fi

    validate_password "$NEW_PASS" && break
    echo "Try again." >&2
done

if ! docker compose -f "$COMPOSE_FILE" ps --status running --services 2>/dev/null | grep -q "^backend$"; then
    echo "Error: backend service is not running. Start with: docker compose up -d" >&2
    exit 1
fi

echo "Resetting password..."

docker compose -f "$COMPOSE_FILE" exec -iT \
    -e "NEW_PASS=$NEW_PASS" \
    -e "TARGET_USER=$TARGET_USER" \
    backend node - <<'JSEOF'
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const { NEW_PASS, TARGET_USER, DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD } = process.env;

(async () => {
    const hash = await bcrypt.hash(NEW_PASS, 12);
    const pool = await mysql.createPool({
        host: DB_HOST,
        port: Number(DB_PORT) || 3306,
        database: DB_NAME,
        user: DB_USER,
        password: DB_PASSWORD,
    });
    const [result] = await pool.execute(
        'UPDATE app_users SET password_hash=?, must_change_password=1 WHERE username=? AND is_admin=1',
        [hash, TARGET_USER]
    );
    await pool.end();
    if (result.affectedRows === 0) {
        console.error(`No admin user found with username: ${TARGET_USER}`);
        process.exit(1);
    }
    console.log(`Password reset for '${TARGET_USER}'. User must change password on next login.`);
})().catch(e => { console.error(e.message); process.exit(1); });
JSEOF
