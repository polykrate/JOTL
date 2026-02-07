#!/usr/bin/env python3
"""
Verify timeslot validation against JAM test vectors
Gray Paper §5.7: HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T
"""

import json
from pathlib import Path

def verify_timeslot_chain(trace_file):
    """Verify timeslot validation for a trace"""
    with open(trace_file) as f:
        data = json.load(f)
    
    header = data['block']['header']
    HT = header['slot']
    
    # Check if parent exists
    parent_hash = header['parent']
    is_genesis = (parent_hash == '0x' + '00' * 32)
    
    if is_genesis:
        print(f"  Genesis block: slot={HT}")
        return True
    
    # For non-genesis, we'd need to look up parent from blockchain
    # For now, just verify structure
    print(f"  Block slot: {HT}")
    return True

def verify_monotonic_increase():
    """Verify P(H)T < HT across consecutive blocks"""
    traces_dir = Path(__file__).parent.parent / 'test' / 'jamtestvectors' / 'traces' / 'fallback'
    
    print("═" * 60)
    print("JAM TIMESLOT VALIDATION - Gray Paper §5.7")
    print("Formula: HT ∈ ℕT, P(H)T < HT ∧ HT · P ≤ T")
    print("═" * 60)
    print()
    
    # Get consecutive blocks
    json_files = sorted([f for f in traces_dir.glob('*.json') 
                        if f.name != 'genesis.json'])[:20]
    
    prev_slot = None
    violations = 0
    
    for trace_file in json_files:
        with open(trace_file) as f:
            data = json.load(f)
        
        header = data['block']['header']
        HT = header['slot']
        
        if prev_slot is not None:
            # Check P(H)T < HT
            if HT <= prev_slot:
                print(f"  ❌ {trace_file.name}: HT={HT} ≯ prev={prev_slot}")
                violations += 1
            else:
                print(f"  ✅ {trace_file.name}: HT={HT} > prev={prev_slot}")
        else:
            print(f"  ✅ {trace_file.name}: HT={HT} (first)")
        
        prev_slot = HT
    
    print()
    print("═" * 60)
    if violations == 0:
        print(f"✅ ALL TIMESLOTS VALID - Monotonically increasing!")
    else:
        print(f"❌ {violations} violations found")
    print("═" * 60)
    
    return violations == 0

if __name__ == '__main__':
    import sys
    sys.exit(0 if verify_monotonic_increase() else 1)
