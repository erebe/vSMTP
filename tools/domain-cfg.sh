CONFIG=$1
DOMAIN=$2

DOMAIN_CFG_PATH="${CONFIG}/domain-available/${DOMAIN}"
INCOMING="${DOMAIN_CFG_PATH}/incoming.vsl"
OUTGOING="${DOMAIN_CFG_PATH}/outgoing.vsl"
INTERNAL="${DOMAIN_CFG_PATH}/internal.vsl"
MAIN="${DOMAIN_CFG_PATH}/main.vsl"

mkdir -p "$DOMAIN_CFG_PATH"

cat >${INCOMING} >${OUTGOING} >${INTERNAL} <<EOF
export const rules = #{

};
EOF

cat >${MAIN} <<EOF
import "domain-available/${DOMAIN}/outoing" as outgoing;
import "domain-available/${DOMAIN}/incoming" as incoming;
import "domain-available/${DOMAIN}/internal" as internal;

#{
    "outgoing": outgoing::rules,
    "incoming": incoming::rules,
    "internal": internal::rules,
}
EOF
