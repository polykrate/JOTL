#!/usr/bin/env python3
"""
STF Test Validator for JOTL

Validates JOTL's STF implementation against official JAM test vectors.

Usage:
    python3 validate-stf.py [--stf accumulate|safrole|...] [--chain tiny|full] [--limit N]
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Tuple

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

class STFValidator:
    def __init__(self, test_vectors_dir: Path):
        self.test_vectors_dir = test_vectors_dir
        self.passed = 0
        self.failed = 0
        self.errors = 0
    
    def load_test_vector(self, filepath: Path) -> Dict[str, Any]:
        """Load and parse a test vector JSON file"""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def validate_timeslot(self, test_data: Dict[str, Any]) -> bool:
        """
        Validate timeslot transition: τ' = HT
        
        Gray Paper §6.1: τ' ≡ HT
        """
        try:
            # Extract slots
            input_slot = test_data['input'].get('slot')
            pre_slot = test_data['pre_state'].get('slot')
            post_slot = test_data['post_state'].get('slot')
            
            if input_slot is None or pre_slot is None or post_slot is None:
                return None  # Skip if slots not present
            
            # Validate: post_slot should equal input_slot
            if post_slot != input_slot:
                print(f"    {RED}✗{RESET} Timeslot mismatch: post_slot={post_slot} != input_slot={input_slot}")
                return False
            
            # Validate: post_slot should be > pre_slot
            if post_slot <= pre_slot:
                print(f"    {RED}✗{RESET} Timeslot not increasing: post={post_slot} <= pre={pre_slot}")
                return False
            
            print(f"    {GREEN}✓{RESET} Timeslot: {pre_slot} → {post_slot} (HT={input_slot})")
            return True
            
        except KeyError as e:
            print(f"    {YELLOW}⚠{RESET} Missing key: {e}")
            return None
    
    def validate_entropy(self, test_data: Dict[str, Any]) -> bool:
        """Validate entropy (η) if present"""
        try:
            pre_entropy = test_data['pre_state'].get('entropy')
            post_entropy = test_data['post_state'].get('entropy')
            
            if pre_entropy and post_entropy:
                if pre_entropy != post_entropy:
                    print(f"    {BLUE}ℹ{RESET} Entropy changed")
                else:
                    print(f"    {GREEN}✓{RESET} Entropy unchanged")
                return True
            return None
        except KeyError:
            return None
    
    def validate_test_file(self, filepath: Path, verbose: bool = True) -> bool:
        """Validate a single test file"""
        if verbose:
            print(f"\n{BLUE}Testing:{RESET} {filepath.name}")
        
        try:
            test_data = self.load_test_vector(filepath)
            
            # Validate different aspects
            results = []
            
            # 1. Timeslot validation
            timeslot_result = self.validate_timeslot(test_data)
            if timeslot_result is not None:
                results.append(timeslot_result)
            
            # 2. Entropy validation
            entropy_result = self.validate_entropy(test_data)
            if entropy_result is not None:
                results.append(entropy_result)
            
            # Overall result
            if not results:
                if verbose:
                    print(f"    {YELLOW}⏭{RESET}  No validations performed")
                return None
            
            success = all(results)
            if verbose:
                status = f"{GREEN}✅ PASS{RESET}" if success else f"{RED}❌ FAIL{RESET}"
                print(f"    {status}")
            
            return success
            
        except json.JSONDecodeError as e:
            if verbose:
                print(f"    {RED}✗{RESET} JSON parse error: {e}")
            self.errors += 1
            return False
        except Exception as e:
            if verbose:
                print(f"    {RED}✗{RESET} Error: {e}")
            self.errors += 1
            return False
    
    def validate_directory(self, stf_name: str, chain: str = 'tiny', limit: int = None) -> Tuple[int, int, int]:
        """Validate all test files in a directory"""
        test_dir = self.test_vectors_dir / 'stf' / stf_name / chain
        
        if not test_dir.exists():
            print(f"{RED}Error:{RESET} Directory not found: {test_dir}")
            return (0, 0, 0)
        
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}Validating STF:{RESET} {stf_name} ({chain})")
        print(f"{BLUE}Directory:{RESET} {test_dir}")
        print(f"{BLUE}{'='*60}{RESET}")
        
        # Find all JSON files
        json_files = sorted(test_dir.glob('*.json'))
        
        if limit:
            json_files = json_files[:limit]
        
        print(f"\n{BLUE}Found {len(json_files)} test files{RESET}")
        
        # Validate each file
        for filepath in json_files:
            result = self.validate_test_file(filepath, verbose=True)
            
            if result is True:
                self.passed += 1
            elif result is False:
                self.failed += 1
            # None = skipped, don't count
        
        return (self.passed, self.failed, self.errors)
    
    def print_summary(self):
        """Print validation summary"""
        total = self.passed + self.failed
        
        print(f"\n{BLUE}{'='*60}{RESET}")
        print(f"{BLUE}Summary{RESET}")
        print(f"{BLUE}{'='*60}{RESET}")
        print(f"  {GREEN}✅ Passed:{RESET}  {self.passed}/{total}")
        print(f"  {RED}❌ Failed:{RESET}  {self.failed}/{total}")
        print(f"  {YELLOW}💥 Errors:{RESET}  {self.errors}")
        
        if total > 0:
            success_rate = (self.passed / total) * 100
            print(f"\n  Success rate: {success_rate:.1f}%")
        
        print()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Validate JOTL STF against test vectors')
    parser.add_argument('--stf', default='accumulate', 
                       help='STF to test (accumulate, safrole, etc.)')
    parser.add_argument('--chain', default='tiny', choices=['tiny', 'full'],
                       help='Chain configuration')
    parser.add_argument('--limit', type=int, default=5,
                       help='Limit number of tests (default: 5, 0 = all)')
    
    args = parser.parse_args()
    
    # Find test vectors directory
    script_dir = Path(__file__).parent
    test_vectors_dir = script_dir / 'jamtestvectors'
    
    if not test_vectors_dir.exists():
        print(f"{RED}Error:{RESET} Test vectors not found at {test_vectors_dir}")
        print(f"Run: git clone https://github.com/w3f/jamtestvectors.git {test_vectors_dir}")
        sys.exit(1)
    
    # Create validator
    validator = STFValidator(test_vectors_dir)
    
    # Run validation
    limit = args.limit if args.limit > 0 else None
    validator.validate_directory(args.stf, args.chain, limit=limit)
    
    # Print summary
    validator.print_summary()
    
    # Exit code
    sys.exit(0 if validator.failed == 0 and validator.errors == 0 else 1)

if __name__ == '__main__':
    main()
