#!/bin/bash

PROGRAM=$1

LOGINS="logins.txt"
DICTIONARY="dictionary.txt"
CRACKED="cracked.txt"
OUTPUT_FILE=""

run_test() {
  local x=$1
  local y=$2
  local data_amount=$((x * y))
  
  start_time=$(date +%s%N)
  $EXECUTABLE $LOGINS $DICTIONARY $CRACKED $x $y
  end_time=$(date +%s%N)
  
  duration=$(( (end_time - start_time) / 1000000 ))
  
  echo "${data_amount},${duration}" >> "$OUTPUT_FILE"
}

if [ -z "$PROGRAM" ]; then
  echo "Nie podano opcji -p. Użycie: $0 <cuda|openmp|sequential>"
  exit 1
fi

case $PROGRAM in
  cuda)
    EXECUTABLE="./cuda/crack_passwords/crack_passwords.o"
    ;;
  openmp)
    EXECUTABLE="./openmp/crack_passwords/crack_passwords.o"
    ;;
  sequential)
    EXECUTABLE="./sequential/crack_passwords/crack_passwords.o"
    ;;
  *)
    echo "Nieprawidłowa wartość dla opcji -p. Dostępne opcje to: cuda, openmp, sequential."
    exit 1
    ;;
esac

OUTPUT_FILE="scores/${PROGRAM}.txt"

mkdir -p scores

> "$OUTPUT_FILE"

for (( y=1; y<=2151220; y+=40000 )); do
  run_test 40000 $y
done

echo "Testy zakończone. Wyniki zapisane w $OUTPUT_FILE."
