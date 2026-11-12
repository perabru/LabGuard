"""TI entrypoint. All original command-line modes and network handlers survive."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if not getattr(sys,'frozen',False):sys.path.insert(0,str(ROOT))

def activate():
    import labguard
    from ti import VERSION
    import labguard.simple_gui as original
    from ti.app import App
    labguard.__version__=VERSION
    original.App=App

def main():
    if '--ti-smoke' in sys.argv:
        from ti.verify import gui_smoke
        folder=Path(sys.argv[sys.argv.index('--output-dir')+1])
        gui_smoke(folder);return 0
    activate()
    import main as network_entry
    return network_entry.run()

if __name__=='__main__':raise SystemExit(main())
