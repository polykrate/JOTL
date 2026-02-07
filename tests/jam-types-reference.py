#!/usr/bin/env python3
"""
Complete JAM Types Reference for JOTL Implementation.
Extracts all structure definitions from jam-types-py.
"""

import inspect
import sys

# Import all jam_types
try:
    from jam_types import *
except ImportError as e:
    print(f"Error: {e}")
    print("Please install: pip install git+https://github.com/davxy/jam-types-py.git")
    sys.exit(1)

def get_type_mapping(cls):
    """Get type_mapping from a class if it exists."""
    if hasattr(cls, 'type_mapping'):
        return cls.type_mapping
    return None

def format_type_mapping(mapping):
    """Format type_mapping for display."""
    if not mapping:
        return None
    
    lines = []
    for field_name, field_type in mapping:
        lines.append(f"    {field_name:30} : {field_type}")
    return "\n".join(lines)

def extract_all_structures():
    """Extract all JAM structure definitions."""
    
    # Import all available types
    from jam_types import (
        Block, Header, EpochMark, TicketsMark,
        Extrinsics, TicketsXt, PreimagesXt, AssurancesXt, DisputesXt, GuaranteesXt,
        TicketBody, TicketEnvelope,
        Preimage,
        AvailAssurance,
        Verdict, Culprit, Fault, Judgement,
        ReportGuarantee, GuaranteeSignature,
        WorkReport, WorkPackageSpec, RefineContext, AuthorizerOutput,
        WorkResults, WorkResult, WorkExecResult,
        WorkPackage, WorkItem,
    )
    
    # Key structures to document
    structures = {
        "Block & Header": [
            ("Block", Block),
            ("Header", Header),
            ("EpochMark", EpochMark),
            ("TicketsMark", TicketsMark),
        ],
        "Extrinsics": [
            ("Extrinsics", Extrinsics),
            ("TicketsXt", TicketsXt),
            ("PreimagesXt", PreimagesXt),
            ("AssurancesXt", AssurancesXt),
            ("DisputesXt", DisputesXt),
            ("GuaranteesXt", GuaranteesXt),
        ],
        "Tickets": [
            ("TicketEnvelope", TicketEnvelope),
            ("TicketBody", TicketBody),
        ],
        "Preimages": [
            ("Preimage", Preimage),
        ],
        "Assurances": [
            ("AvailAssurance", AvailAssurance),
        ],
        "Disputes": [
            ("Verdict", Verdict),
            ("Culprit", Culprit),
            ("Fault", Fault),
            ("Judgement", Judgement),
        ],
        "Guarantees": [
            ("ReportGuarantee", ReportGuarantee),
            ("GuaranteeSignature", GuaranteeSignature),
        ],
        "Work Report": [
            ("WorkReport", WorkReport),
            ("WorkPackageSpec", WorkPackageSpec),
            ("RefineContext", RefineContext),
            ("AuthorizerOutput", AuthorizerOutput),
            ("WorkResults", WorkResults),
            ("WorkResult", WorkResult),
            ("WorkExecResult", WorkExecResult),
        ],
        "Work Package": [
            ("WorkPackage", WorkPackage),
            ("WorkItem", WorkItem),
        ],
    }
    
    print("=" * 80)
    print("JAM TYPES REFERENCE - Complete Structure Definitions")
    print("For JOTL (Common Lisp Implementation)")
    print("=" * 80)
    print()
    
    for category, items in structures.items():
        print("\n" + "=" * 80)
        print(f"📦 {category}")
        print("=" * 80)
        
        for name, cls in items:
            print(f"\n{name}")
            print("-" * 80)
            
            mapping = get_type_mapping(cls)
            if mapping:
                print("Fields:")
                print(format_type_mapping(mapping))
            else:
                # Try to get from __init__ signature
                try:
                    sig = inspect.signature(cls.__init__)
                    params = list(sig.parameters.items())[1:]  # Skip 'self'
                    if params:
                        print("Fields:")
                        for param_name, param in params:
                            annotation = param.annotation
                            if annotation != inspect.Parameter.empty:
                                type_str = str(annotation).replace('typing.', '')
                            else:
                                type_str = "?"
                            print(f"    {param_name:30} : {type_str}")
                except:
                    pass
            
            # Check if it's a Vec or Struct
            if hasattr(cls, '__bases__'):
                bases = [b.__name__ for b in cls.__bases__]
                if bases != ['object']:
                    print(f"\nInherits from: {', '.join(bases)}")
            
            # Check for sub_type (for Vec types)
            if hasattr(cls, 'sub_type'):
                print(f"\nVec of: {cls.sub_type}")
    
    print("\n" + "=" * 80)
    print("EXTRACTION COMPLETE")
    print("=" * 80)
    print("\n💡 Use this reference to implement missing structures in JOTL!")

if __name__ == "__main__":
    extract_all_structures()
