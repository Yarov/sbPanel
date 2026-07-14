#!/bin/bash
# Prueba bidireccional: A y B agregan un record CADA UNO ~al mismo tiempo (divergencia).
# Deben converger AMBOS a los 2 records, sin que nadie pise a nadie.
BIN=/Users/yarov/scotia/dashboard/spike/target/debug/p2p-crdt-spike
A=/tmp/spike_bi_A.log
B=/tmp/spike_bi_B.log
rm -f "$A" "$B"

(sleep 9; echo "tarea-de-A"; sleep 21) | "$BIN" > "$A" 2>&1 &
APID=$!
(sleep 9; echo "tarea-de-B"; sleep 21) | "$BIN" > "$B" 2>&1 &
BPID=$!

sleep 22
kill $APID $BPID 2>/dev/null
wait 2>/dev/null

echo "===== NODO A (estado final) ====="; tail -4 "$A"
echo ""; echo "===== NODO B (estado final) ====="; tail -4 "$B"
echo ""; echo "===== VEREDICTO ====="
# Cada nodo debe tener AMBOS records en su estado.
a_ok=$(grep -c "tarea-de-A" "$A"); a_has_b=$(grep -c "tarea-de-B" "$A")
b_ok=$(grep -c "tarea-de-B" "$B"); b_has_a=$(grep -c "tarea-de-A" "$B")
if [ "$a_has_b" -gt 0 ] && [ "$b_has_a" -gt 0 ]; then
  echo "PASS: ambos convergieron a los 2 records — nadie pisó a nadie (merge bidireccional OK)"
else
  echo "FAIL: A_tiene_B=$a_has_b  B_tiene_A=$b_has_a"
fi
