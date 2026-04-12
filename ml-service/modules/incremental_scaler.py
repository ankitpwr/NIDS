"""
Compatibility shim for legacy preprocessor.pkl artifacts.

Confirmed attribute names from pickle inspection:
    median_   shape=(33,)  → maps to RobustScaler.center_
    scale_    shape=(33,)  → maps to RobustScaler.scale_  (already correct name)
    iqr_      shape=(33,)  → same values as scale_, ignored
"""

from sklearn.preprocessing import RobustScaler
import numpy as np


class RobustIncrementalScaler:

    def __setstate__(self, state: dict):
        """
        Called by pickle instead of __init__.
        Absorbs the old state and maps known attribute names to what we need.
        """
        # Absorb everything the old pickle stored
        self.__dict__.update(state)

        # _sklearn_scaler was never in the pickle — always create fresh
        self._sklearn_scaler = None

        # center_ = median_ (confirmed from pickle inspection)
        if not hasattr(self, "center_"):
            self.center_ = self.__dict__.get("median_", None)

        # scale_ is already stored as scale_ in the pickle — nothing to remap.
        # But guarantee it exists as a plain attribute either way.
        if not hasattr(self, "scale_"):
            self.scale_ = self.__dict__.get("iqr_", None)

        # Safety: replace any zero scales to avoid division by zero
        if self.scale_ is not None:
            arr = np.asarray(self.scale_, dtype=np.float64)
            arr[arr == 0] = 1.0
            self.scale_ = arr

        if self.center_ is not None:
            self.center_ = np.asarray(self.center_, dtype=np.float64)

    def _build_sklearn_scaler(self) -> RobustScaler:
        scaler = RobustScaler()
        center = getattr(self, "center_", None)
        scale  = getattr(self, "scale_",  None)

        if center is not None and scale is not None:
            scaler.center_        = center
            scaler.scale_         = scale
            scaler.n_features_in_ = len(center)

        return scaler

    def transform(self, X):
        if self._sklearn_scaler is None:
            self._sklearn_scaler = self._build_sklearn_scaler()

        sk = self._sklearn_scaler
        if hasattr(sk, "center_") and sk.center_ is not None:
            return sk.transform(X)

        # Fallback: no stats — return X unchanged
        return np.asarray(X, dtype=np.float64)

    def fit_transform(self, X):
        self._sklearn_scaler = RobustScaler().fit(X)
        self.center_ = self._sklearn_scaler.center_
        self.scale_  = self._sklearn_scaler.scale_
        return self._sklearn_scaler.transform(X)

    def partial_fit(self, X):
        return self

    def get_stats(self):
        center = getattr(self, "center_", None)
        scale  = getattr(self, "scale_",  None)
        return {
            "center":         center.tolist() if center is not None else None,
            "scale":          scale.tolist()  if scale  is not None else None,
            "n_samples_seen": getattr(self, "n_samples_", 0),
        }


IncrementalScaler = RobustIncrementalScaler