#!/bin/bash
# Start SBCL REPL with JOTL loaded

cd /home/polycrate/Projets/JOTL

echo "Loading JOTL v3..."
echo "(load \"scripts/load-jotl.lisp\")" | sbcl
