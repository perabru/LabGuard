"""Gera os dois executáveis no Windows sem instalar a proteção na máquina."""
from __future__ import annotations
import os
from pathlib import Path
import struct
import subprocess
import sys
import venv


def main():
    if os.name != 'nt' or struct.calcsize('P') != 8 or sys.version_info < (3, 10):
        raise RuntimeError('Use Windows com Python 3.10+ de 64 bits. Recomendado: Python 3.12 com Tcl/Tk.')
    import tkinter  # A interface administrativa precisa acompanhar o interpretador.
    project = Path(__file__).resolve().parents[1]
    folder = project / '.venv-central-build'
    venv.EnvBuilder(with_pip=True).create(folder)
    python = str(folder / 'Scripts' / 'python.exe')
    def run(*args):
        subprocess.run([python, *args], cwd=project, check=True)
    run('-m', 'pip', 'install', '--disable-pip-version-check', '-r', 'central/requirements.txt', 'pyinstaller==6.22.3')
    run('-m', 'unittest', 'discover', '-s', 'client', '-p', 'test_*.py')
    run('-m', 'unittest', 'discover', '-s', 'central', '-p', 'test_*.py')
    run('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--windowed', '--noupx',
        '--name', 'LabGuardCliente', '--distpath', 'Executaveis', '--workpath', 'build/cliente-local',
        '--specpath', 'build', 'client/labguard_cliente.py')
    run('-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--windowed', '--uac-admin', '--noupx',
        '--name', 'LabGuardTecnico', '--paths', '.', '--paths', 'client', '--paths', 'central',
        '--add-data', str(project / 'central' / 'assets') + ';assets', '--distpath', 'Executaveis', '--workpath', 'build/central-local',
        '--specpath', 'build', 'central/labguard_tecnico.py')
    print('\nArquivos gerados na pasta Executaveis:')
    print('LabGuardTecnico.exe: instalar no PC do tecnico.')
    print('LabGuardCliente.exe: instalar nos PCs dos alunos.')
    print('Leia central/README.md para configurar e vincular uma estacao piloto.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('A compilacao nao terminou: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
