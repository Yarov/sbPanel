#!/bin/bash
# Prueba de convergencia: nodo A agrega un record, nodo B debe recibirlo por mDNS+gossipsub.
BIN=/Users/yarov/scotia/dashboard/spike/target/debug/p2p-crdt-spike
A=/tmp/spike_A.log
B=/tmp/spike_B.log
rm -f "$A" "$B"

# Nodo B: solo escucha, stdin abierto 30s para no cerrar el proceso.
(sleep 30) | "$BIN" > "$B" 2>&1 &
BPID=$!

# Nodo A: espera 9s a que haya discovery, manda un record, sigue vivo.
(sleep 9; echo "hola-desde-A"; sleep 21) | "$BIN" > "$A" 2>&1 &
APID=$!

sleep 20
kill $BPID $APID 2>/dev/null
wait 2>/dev/null

echo "===== NODO A ====="
cat "$A"
echo ""
echo "===== NODO B ====="
cat "$B"
echo ""
echo "===== VEREDICTO ====="
if grep -q "hola-desde-A" "$B"; then
  echo "PASS: el record de A llegó a B (mDNS + gossipsub + merge OK)"
else
  echo "FAIL: B no recibió el record de A"
fi
