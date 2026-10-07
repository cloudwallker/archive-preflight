"""Windows-only standalone build using the exact installed development lock."""
import argparse
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.name!='nt':raise SystemExit('Build the Windows executable on Windows.')
    if importlib.metadata.version('pyinstaller')!='6.22.3':raise SystemExit('Install requirements-build.txt first.')
    root=Path(__file__).resolve().parents[1]
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,default=root/'dist');args=parser.parse_args()
    args.output.mkdir(exist_ok=True)
    env=dict(os.environ,PYINSTALLER_CONFIG_DIR=str(root/'build/tool-cache'),PYTHONUTF8='1')
    subprocess.run([sys.executable,'-m','PyInstaller','--noconfirm','--clean','--onefile','--console','--name','archive-preflight',
                    '--paths',str(root/'src'),'--add-data',str(root/'src/archive_preflight/assets')+os.pathsep+'archive_preflight/assets',
                    '--add-data',str(root/'licenses')+os.pathsep+'licenses','--add-data',str(root/'THIRD_PARTY_NOTICES.md')+os.pathsep+'.',
                    '--add-data',str(root/'LICENSE')+os.pathsep+'.',
                    '--distpath',str(args.output),'--workpath',str(root/'build'),'--specpath',str(root/'build'),str(root/'src/archive_preflight/__main__.py')],cwd=root,env=env,check=True)


if __name__=='__main__':main()
