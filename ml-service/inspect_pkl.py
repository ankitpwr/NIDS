"""
Run this ONCE from inside ml-service/ to see exactly what attribute names
the old RobustIncrementalScaler stored in the pickle.

Usage:
    cd ml-service
    python inspect_pkl.py
"""

import pickle
import sys

PKL_PATH = "artifacts/preprocessor.pkl"

# Minimal stub so pickle can deserialise the object without the real class
class _AnyObject:
    def __setstate__(self, state):
        self.__dict__.update(state)
        self._captured_state = state   # keep a copy

import types, importlib

# Patch the modules namespace so pickle finds our stub
fake_module = types.ModuleType("modules.incremental_scaler")
fake_module.RobustIncrementalScaler = _AnyObject
fake_module.IncrementalScaler       = _AnyObject
sys.modules["modules.incremental_scaler"] = fake_module

with open(PKL_PATH, "rb") as f:
    preprocessor = pickle.load(f)

scaler = preprocessor.scaler
print("=" * 60)
print("Scaler type:", type(scaler).__name__)
print()
print("All attributes stored in the pickle:")
for k, v in sorted(vars(scaler).items()):
    if hasattr(v, "shape"):
        print(f"  {k:30s}  shape={v.shape}  dtype={v.dtype}  first3={v.flat[:3]}")
    elif isinstance(v, (list, tuple)) and len(v) > 0:
        print(f"  {k:30s}  len={len(v)}  first3={v[:3]}")
    else:
        print(f"  {k:30s}  = {repr(v)[:80]}")
print("=" * 60)
print()
print("Paste the output above and the correct attribute names will be clear.")
print("Then update incremental_scaler.py __setstate__ with the right names.")