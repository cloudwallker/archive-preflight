"""SafeTree policy and accounting; every filesystem operation has a native backend."""
import hashlib
import os
from pathlib import Path
import zlib

from .model import CleanupResult, Diagnostic, ExtractLimits, OutputBudget, WrittenEntry


class UnsupportedHost(ValueError):
    pass


class OwnershipUnknown(ValueError):
    pass


class FileCreatedError(OSError):
    """Exclusive creation succeeded, but a verified writer could not be returned."""
    pass


def checked_parts(parts):
    if not isinstance(parts, tuple) or not parts or len(parts) > 64:
        raise ValueError('HOST_NAME_UNSUPPORTED')
    for part in parts:
        if type(part) is not str or not part or part in ('.','..') or any(c in part for c in '/\\\0'):
            raise ValueError('HOST_NAME_UNSUPPORTED')
        if os.name == 'nt':
            stem = part.split('.')[0].rstrip(' .').upper()
            if (part[-1] in '. ' or any(ord(c)<32 or c in '<>:"|?*' for c in part)
                    or stem in ('CON','PRN','AUX','NUL','CONIN$','CONOUT$')
                    or stem in tuple(p+n for p in ('COM','LPT') for n in '123456789¹²³')
                    or len(part.encode('utf-16-le'))//2 > 255):
                raise ValueError('HOST_NAME_UNSUPPORTED')
        else:
            try:
                if len(os.fsencode(part)) > 255:
                    raise ValueError('HOST_NAME_UNSUPPORTED')
            except UnicodeError:
                raise ValueError('HOST_NAME_UNSUPPORTED') from None
    return parts


class SafeTree:
    @staticmethod
    def create(output: Path):
        if os.name == 'nt':
            try:
                from .safe_fs_windows import WindowsTree
            except (ImportError,AttributeError,OSError):
                raise UnsupportedHost('NATIVE_BACKEND_UNAVAILABLE') from None
            return WindowsTree(output)
        if os.name == 'posix':
            from .safe_fs_posix import PosixTree
            return PosixTree(output)
        raise UnsupportedHost('UNSUPPORTED_HOST')


class _Tree:
    def _initialize(self, output):
        self.output = Path(os.path.abspath(output))
        self.limits, self.budget = ExtractLimits(), OutputBudget()
        self.nodes, self.ancestors = {}, []
        self.closed = False
        self.created = False

    def _check_chain(self, parts):
        if self.closed:
            raise OwnershipUnknown('CLOSED_HANDLES')
        for node in self.ancestors:
            self._verify(node)
        for depth in range(len(parts)+1):
            if parts[:depth] in self.nodes:
                self._verify(self.nodes[parts[:depth]])

    def mkdir(self, parts):
        checked_parts(parts)
        for depth in range(1,len(parts)+1):
            current = parts[:depth]
            self._check_chain(current)
            if current in self.nodes:
                if self.nodes[current]['kind'] != 'directory':
                    raise ValueError('HOST_PATH_CONFLICT')
                continue
            if self.budget.directories >= self.limits.directories:
                raise ValueError('ACTUAL_DIRECTORY_LIMIT')
            node = self._mkdir(current)
            self.nodes[current] = node

    def create_file(self, parts):
        checked_parts(parts)
        if len(parts)>1:
            self.mkdir(parts[:-1])
        self._check_chain(parts[:-1])
        if parts in self.nodes:
            raise ValueError('OUTPUT_ALREADY_EXISTS')
        node, stream = self._create_file(parts)
        self.nodes[parts] = node
        return stream

    def list_verified(self):
        self._check_chain(())
        expected = set(self.nodes)-{()}
        actual = set()
        for parts, node in self.nodes.items():
            self._verify(node)
            if node['kind'] == 'directory':
                for name, identity, kind in self._list(node):
                    child = parts+(name,)
                    if child not in self.nodes or identity != self.nodes[child]['identity'] or kind != self.nodes[child]['kind']:
                        raise OwnershipUnknown('OUTPUT_SET_CHANGED')
                    actual.add(child)
        if actual != expected:
            raise OwnershipUnknown('OUTPUT_SET_CHANGED')
        result = []
        for parts in sorted(expected):
            node = self.nodes[parts]
            if node['kind'] == 'directory':
                result.append(WrittenEntry(None,'/'.join(parts),'directory',0))
                continue
            size, crc, digest = 0, 0, hashlib.sha256()
            with self._read_file(node) as source:
                while block := source.read(self.limits.chunk_bytes):
                    size += len(block)
                    if size > self.limits.file_bytes:
                        raise OwnershipUnknown('OUTPUT_SIZE_CHANGED')
                    crc = zlib.crc32(block,crc)
                    digest.update(block)
            self._verify(node)
            result.append(WrittenEntry(None,'/'.join(parts),'file',size,crc,digest.hexdigest()))
        return tuple(result)

    def cleanup_owned(self):
        if not self.created:
            return CleanupResult('not_created')
        try:
            self.list_verified()
        except (OSError,ValueError):
            return CleanupResult('retained_ownership_unknown', diagnostics=(Diagnostic('CLEANUP_OWNERSHIP_UNKNOWN'),))
        removed_files = removed_dirs = 0
        try:
            for parts in sorted(self.nodes,key=lambda p:(len(p),p),reverse=True):
                node = self.nodes[parts]
                self._verify(node)
                self._remove(node)
                if node['kind']=='directory':
                    removed_dirs += 1
                else:
                    removed_files += 1
            self.created = False
            return CleanupResult('removed',removed_files,removed_dirs)
        except OwnershipUnknown:
            return CleanupResult('retained_ownership_unknown',removed_files,removed_dirs,(Diagnostic('CLEANUP_OWNERSHIP_UNKNOWN'),))
        except OSError:
            return CleanupResult('cleanup_failed',removed_files,removed_dirs,(Diagnostic('CLEANUP_IO_ERROR'),))

    def close(self):
        if self.closed:
            return
        failed = False
        for node in list(self.nodes.values())[::-1]+self.ancestors[::-1]:
            try:
                self._close_node(node)
            except OSError:
                failed = True
        self.closed = True
        if failed:
            raise OSError('HANDLE_CLOSE_FAILED')
