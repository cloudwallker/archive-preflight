"""Source and PyInstaller entry point; dispatch frozen multiprocessing first."""
import multiprocessing

if __name__ == '__main__':
    multiprocessing.freeze_support()
    from archive_preflight.cli import main
    raise SystemExit(main())
