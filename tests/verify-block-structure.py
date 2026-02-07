#!/usr/bin/env python3
"""
Verify block structure against JAM test vector
Gray Paper §4.2 and §5.1

Test vector: test/jamtestvectors/codec/tiny/block.json
"""

import json
from pathlib import Path

def verify_header_structure(header):
    """Verify header matches Gray Paper §5.1
    
    H ≡ (HP, HR, HX, HT, HE, HW, HO, HI, HV, HS)
    """
    print("\n╔═══════════════════════════════════════════════╗")
    print("║  HEADER STRUCTURE (Gray Paper §5.1)         ║")
    print("╚═══════════════════════════════════════════════╝\n")
    
    required_fields = {
        'parent': 'HP',
        'parent_state_root': 'HR', 
        'extrinsic_hash': 'HX',
        'slot': 'HT',
        'epoch_mark': 'HE',
        'tickets_mark': 'HW',
        'offenders_mark': 'HO',
        'author_index': 'HI',
        'entropy_source': 'HV',
        'seal': 'HS'
    }
    
    print("Checking all 10 header components:\n")
    
    all_present = True
    for field, symbol in required_fields.items():
        if field in header:
            value = header[field]
            
            # Display field info
            if isinstance(value, str):
                display = f"{value[:20]}..." if len(value) > 20 else value
            elif isinstance(value, int):
                display = value
            elif isinstance(value, dict):
                display = f"{{...}} ({len(value)} keys)"
            elif isinstance(value, list):
                display = f"[...] ({len(value)} items)"
            elif value is None:
                display = "null"
            else:
                display = str(value)
            
            print(f"  ✅ {symbol:3} ({field:20}): {display}")
        else:
            print(f"  ❌ {symbol:3} ({field:20}): MISSING")
            all_present = False
    
    print()
    
    # Detailed component analysis
    print("Component details:\n")
    
    # HP - Parent hash
    hp = header['parent']
    print(f"  HP (parent):")
    print(f"    Value: {hp}")
    print(f"    Type:  32-byte hash (0x + 64 hex chars)")
    print(f"    Valid: {len(hp) == 66 and hp.startswith('0x')}")
    print()
    
    # HT - Timeslot
    ht = header['slot']
    print(f"  HT (slot):")
    print(f"    Value: {ht}")
    print(f"    Type:  Natural number (τ')")
    print(f"    Valid: {isinstance(ht, int) and ht >= 0}")
    print()
    
    # HE - Epoch mark
    he = header['epoch_mark']
    if he:
        print(f"  HE (epoch_mark):")
        print(f"    entropy:         {he['entropy'][:20]}...")
        print(f"    tickets_entropy: {he['tickets_entropy'][:20]}...")
        print(f"    validators:      {len(he['validators'])} validators")
        for i, v in enumerate(he['validators'][:2]):
            print(f"      Validator {i}:")
            print(f"        bandersnatch: {v['bandersnatch'][:20]}...")
            print(f"        ed25519:      {v['ed25519'][:20]}...")
        if len(he['validators']) > 2:
            print(f"      ... and {len(he['validators']) - 2} more")
    else:
        print(f"  HE (epoch_mark): null")
    print()
    
    # HW - Tickets mark
    hw = header['tickets_mark']
    print(f"  HW (tickets_mark): {hw}")
    print()
    
    # HO - Offenders mark
    ho = header['offenders_mark']
    print(f"  HO (offenders_mark): {len(ho)} offenders")
    for i, offender in enumerate(ho):
        print(f"    {i}: {offender}")
    print()
    
    # HI - Author index
    hi = header['author_index']
    print(f"  HI (author_index): {hi}")
    print()
    
    # HV - VRF signature
    hv = header['entropy_source']
    print(f"  HV (entropy_source):")
    print(f"    Value: {hv[:40]}...")
    print(f"    Length: {len(hv)} chars (0x + hex)")
    print(f"    Type: Bandersnatch VRF signature (96 bytes)")
    print()
    
    # HS - Seal
    hs = header['seal']
    print(f"  HS (seal):")
    print(f"    Value: {hs[:40]}...")
    print(f"    Length: {len(hs)} chars (0x + hex)")
    print(f"    Type: Bandersnatch signature (96 bytes)")
    print()
    
    return all_present

def verify_extrinsic_structure(extrinsic):
    """Verify extrinsic matches Gray Paper §4.3
    
    E ≡ (ET, ED, EP, EA, EG)
    """
    print("\n╔═══════════════════════════════════════════════╗")
    print("║  EXTRINSIC STRUCTURE (Gray Paper §4.3)      ║")
    print("╚═══════════════════════════════════════════════╝\n")
    
    required_fields = {
        'tickets': 'ET',
        'disputes': 'ED',
        'preimages': 'EP',
        'assurances': 'EA',
        'guarantees': 'EG'
    }
    
    print("Checking all 5 extrinsic components:\n")
    
    all_present = True
    for field, symbol in required_fields.items():
        if field in extrinsic:
            value = extrinsic[field]
            
            if isinstance(value, list):
                print(f"  ✅ {symbol:3} ({field:12}): {len(value)} items")
            elif isinstance(value, dict):
                # Disputes is a dict, not a list
                print(f"  ✅ {symbol:3} ({field:12}): {{...}}")
            else:
                print(f"  ✅ {symbol:3} ({field:12}): {value}")
        else:
            print(f"  ❌ {symbol:3} ({field:12}): MISSING")
            all_present = False
    
    print()
    
    # Detailed component analysis
    print("Component details:\n")
    
    # ET - Tickets
    et = extrinsic['tickets']
    print(f"  ET (tickets): {len(et)} tickets")
    for i, ticket in enumerate(et):
        print(f"    Ticket {i}:")
        print(f"      attempt:   {ticket['attempt']}")
        print(f"      signature: {ticket['signature'][:40]}...")
    print()
    
    # EP - Preimages
    ep = extrinsic['preimages']
    print(f"  EP (preimages): {len(ep)} preimages")
    for i, preimage in enumerate(ep):
        print(f"    Preimage {i}:")
        print(f"      requester: {preimage['requester']}")
        print(f"      blob:      {preimage['blob']}")
    print()
    
    # EG - Guarantees
    eg = extrinsic['guarantees']
    print(f"  EG (guarantees): {len(eg)} guarantees")
    for i, guarantee in enumerate(eg):
        print(f"    Guarantee {i}:")
        print(f"      slot:       {guarantee['slot']}")
        print(f"      signatures: {len(guarantee['signatures'])} signatures")
        report = guarantee['report']
        print(f"      report:")
        print(f"        core_index:      {report['core_index']}")
        print(f"        authorizer_hash: {report['authorizer_hash'][:20]}...")
        print(f"        results:         {len(report['results'])} results")
    print()
    
    # EA - Assurances
    ea = extrinsic['assurances']
    print(f"  EA (assurances): {len(ea)} assurances")
    for i, assurance in enumerate(ea):
        print(f"    Assurance {i}:")
        print(f"      validator_index: {assurance['validator_index']}")
        print(f"      anchor:          {assurance['anchor'][:20]}...")
        print(f"      bitfield:        {assurance['bitfield']}")
    print()
    
    # ED - Disputes
    ed = extrinsic['disputes']
    print(f"  ED (disputes):")
    print(f"    verdicts: {len(ed['verdicts'])} verdicts")
    print(f"    culprits: {len(ed['culprits'])} culprits")
    print(f"    faults:   {len(ed['faults'])} faults")
    print()
    
    return all_present

def verify_block_structure():
    """Verify complete block structure
    
    B ≡ (H, E)
    """
    block_file = Path(__file__).parent.parent / 'test' / 'jamtestvectors' / 'codec' / 'tiny' / 'block.json'
    
    print("═" * 60)
    print("JAM BLOCK STRUCTURE VERIFICATION")
    print("Gray Paper §4.2: B ≡ (H, E)")
    print("═" * 60)
    print(f"\nTest vector: {block_file.name}")
    
    with open(block_file) as f:
        block = json.load(f)
    
    # Check top-level structure
    print("\n╔═══════════════════════════════════════════════╗")
    print("║  BLOCK STRUCTURE (Gray Paper §4.2)          ║")
    print("╚═══════════════════════════════════════════════╝\n")
    
    if 'header' in block and 'extrinsic' in block:
        print("  ✅ B = (H, E) structure present")
        print(f"    H (header):    {type(block['header']).__name__}")
        print(f"    E (extrinsic): {type(block['extrinsic']).__name__}")
    else:
        print("  ❌ Missing header or extrinsic")
        return False
    
    # Verify header
    header_valid = verify_header_structure(block['header'])
    
    # Verify extrinsic
    extrinsic_valid = verify_extrinsic_structure(block['extrinsic'])
    
    # Summary
    print("\n═" * 60)
    if header_valid and extrinsic_valid:
        print("✅ BLOCK STRUCTURE VALID - Matches Gray Paper!")
        print("\nSummary:")
        print("  • Header H has all 10 components (§5.1)")
        print("  • Extrinsic E has all 5 components (§4.3)")
        print("  • Block B = (H, E) structure correct (§4.2)")
    else:
        print("❌ BLOCK STRUCTURE INVALID")
    print("═" * 60)
    
    return header_valid and extrinsic_valid

if __name__ == '__main__':
    import sys
    sys.exit(0 if verify_block_structure() else 1)
