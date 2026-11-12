"""LabGuard Central 1.1 with authenticated local-school alerts."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if not getattr(sys,'frozen',False):
    for p in (ROOT,ROOT/'central',ROOT/'client',ROOT/'managed'):
        sys.path.insert(0,str(p))
import alerts
alerts.install()
import labguard_tecnico
labguard_tecnico.CENTRAL_VERSION='1.1.0'
if __name__=='__main__':
    raise SystemExit(labguard_tecnico.main())
