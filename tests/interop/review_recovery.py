#!/usr/bin/env python3
"""Three independent reviews bound to the recovery claims, source, validators and selected gem."""
import review_inspection

if __name__=='__main__':
    review_inspection.CLAIMS='docs/recovery-export-0.6.0.md'
    raise SystemExit(review_inspection.main())
