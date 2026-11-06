"""Valida uma janela Tk real do pacote Linux dentro do Xvfb do CI."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main():
    executable = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stderr:
        process = subprocess.Popen([executable], stdout=subprocess.DEVNULL, stderr=stderr)
        try:
            for _ in range(60):
                if process.poll() is not None:
                    stderr.seek(0)
                    raise RuntimeError("O painel encerrou durante a abertura: " + stderr.read()[-2000:])
                result = subprocess.run(["xwininfo", "-root", "-tree"], capture_output=True, text=True, check=True)
                if "LabGuard" in result.stdout:
                    time.sleep(1)
                    if process.poll() is not None:
                        raise RuntimeError("O painel encerrou após criar a janela.")
                    stderr.seek(0)
                    errors = stderr.read()
                    if "Traceback (most recent call last)" in errors:
                        raise RuntimeError(errors[-2000:])
                    print("PASS: janela gráfica LabGuard aberta no Linux sem erro de inicialização.")
                    return
                time.sleep(0.2)
            raise RuntimeError("A janela LabGuard não apareceu no X11 do teste.")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    main()
