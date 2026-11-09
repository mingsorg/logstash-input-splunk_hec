#!/usr/bin/env python3
"""Bind three independent review lenses to the 0.5.0 claims and exact gem."""
import review_inspection
from check_metrics_qualification import CLAIMS

if __name__=='__main__':
    review_inspection.CLAIMS=CLAIMS
    raise SystemExit(review_inspection.main())
