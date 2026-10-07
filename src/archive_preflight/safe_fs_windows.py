"""Local NTFS: retained non-delete-shared directory handles and CREATE_NEW files.

The trusted-parent/no-hostile-same-account boundary applies to mkdir-to-open.
No pathname recursion or fallback filesystem implementation is used.
"""
import ctypes
from ctypes import wintypes as w
import msvcrt
import os

from .safe_fs import _Tree, OwnershipUnknown, UnsupportedHost, FileCreatedError, checked_parts

k = ctypes.WinDLL('kernel32', use_last_error=True)


def _bind(name, args, result=w.BOOL):
    fn = getattr(k,name)
    fn.argtypes, fn.restype = args,result
    return fn


_create = _bind('CreateFileW',(w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE),w.HANDLE)
_close = _bind('CloseHandle',(w.HANDLE,))
_mkdir = _bind('CreateDirectoryW',(w.LPCWSTR,w.LPVOID))
_query = _bind('GetFileInformationByHandleEx',(w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD))
_info = _bind('GetFileInformationByHandle',(w.HANDLE,w.LPVOID))
_final = _bind('GetFinalPathNameByHandleW',(w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD),w.DWORD)
_set = _bind('SetFileInformationByHandle',(w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD))
_volume = _bind('GetVolumeInformationByHandleW',(w.HANDLE,w.LPWSTR,w.DWORD,w.LPVOID,w.LPVOID,w.LPVOID,w.LPWSTR,w.DWORD))
_drive = _bind('GetDriveTypeW',(w.LPCWSTR,),w.UINT)
_dup = _bind('DuplicateHandle',(w.HANDLE,w.HANDLE,w.HANDLE,ctypes.POINTER(w.HANDLE),w.DWORD,w.BOOL,w.DWORD))
_process = _bind('GetCurrentProcess',(),w.HANDLE)


class _Info(ctypes.Structure):
    _fields_ = [('attr',w.DWORD),('created',w.FILETIME),('accessed',w.FILETIME),('written',w.FILETIME),
                ('volume',w.DWORD),('size_hi',w.DWORD),('size_lo',w.DWORD),('links',w.DWORD),('id_hi',w.DWORD),('id_lo',w.DWORD)]


class _DirInfo(ctypes.Structure):
    _fields_ = [('next',w.DWORD),('index',w.DWORD),('created',ctypes.c_longlong),('accessed',ctypes.c_longlong),
                ('written',ctypes.c_longlong),('changed',ctypes.c_longlong),('size',ctypes.c_longlong),('allocated',ctypes.c_longlong),
                ('attr',w.DWORD),('name_len',w.DWORD),('ea',w.DWORD),('short_len',ctypes.c_byte),('short',w.WCHAR*12),
                ('file_id',ctypes.c_longlong),('name',w.WCHAR*1)]


def _error():
    return ctypes.WinError(ctypes.get_last_error())


def _path(path):
    return '\\\\?\\'+str(path)


def _snapshot(handle, path, directory):
    info = _Info()
    if not _info(handle,ctypes.byref(info)):
        raise _error()
    tag = (w.DWORD*2)()
    if not _query(handle,9,tag,ctypes.sizeof(tag)):
        raise _error()
    if tag[0]&0x400 or bool(tag[0]&0x10)!=directory or (not directory and info.links!=1):
        raise OwnershipUnknown('REPARSE_OR_TYPE_CHANGED')
    buf = ctypes.create_unicode_buffer(32768)
    length = _final(handle,buf,len(buf),0)
    if not 0 < length < len(buf):
        raise _error()
    if os.path.normcase(buf.value.rstrip('\\')) != os.path.normcase(_path(path).rstrip('\\')):
        raise OwnershipUnknown('FINAL_PATH_CHANGED')
    return (info.volume, info.id_hi<<32|info.id_lo)


def _open(path, directory, owned=False, new=False):
    access = (0x80 if directory and not owned else 0x80000000) | (0x10000 if owned else 0) | (0x40000000 if new else 0)
    # Directory write sharing is needed by benign hosts; DELETE is never shared.
    share = 3 if directory else 1
    handle = _create(_path(path),access,share,None,1 if new else 3,0x00200000|(0x02000000 if directory else 0),None)
    if handle == ctypes.c_void_p(-1).value:
        raise _error()
    try:
        identity = _snapshot(handle,path,directory)
        return {'handle':handle,'path':path,'identity':identity,'kind':'directory' if directory else 'file'}
    except BaseException:
        _close(handle)
        if new:
            raise FileCreatedError('FILE_IDENTITY_UNVERIFIED') from None
        raise


def _stream(node, writing=False):
    duplicate = w.HANDLE()
    process = _process()
    if not _dup(process,node['handle'],process,ctypes.byref(duplicate),0,False,2):
        raise _error()
    try:
        fd = msvcrt.open_osfhandle(duplicate.value,os.O_BINARY|(os.O_RDWR if writing else os.O_RDONLY))
    except BaseException:
        _close(duplicate)
        raise
    stream = os.fdopen(fd,'r+b' if writing else 'rb',buffering=0)
    try:
        stream.seek(0)
    except BaseException:
        stream.close()
        raise
    return stream


class WindowsTree(_Tree):
    backend = 'windows-ntfs-native'

    def __init__(self,output):
        self._initialize(output)
        if self.output.drive.startswith('\\') or len(self.output.drive)!=2 or _drive(self.output.anchor)!=3:
            raise UnsupportedHost('LOCAL_NTFS_REQUIRED')
        checked_parts((self.output.name,))
        try:
            current = self.output.__class__(self.output.anchor)
            for part in (None,)+self.output.parts[1:-1]:
                if part is not None:
                    current /= part
                try:
                    node = _open(current,True)
                except OSError:
                    raise UnsupportedHost('NATIVE_ANCESTOR_UNAVAILABLE') from None
                self.ancestors.append(node)
                filesystem = ctypes.create_unicode_buffer(64)
                if not _volume(node['handle'],None,0,None,None,None,filesystem,len(filesystem)):
                    raise UnsupportedHost('VOLUME_CHECK_UNAVAILABLE')
                if filesystem.value != 'NTFS':
                    raise UnsupportedHost('LOCAL_NTFS_REQUIRED')
            if not _mkdir(_path(self.output),None):
                raise _error()
            self.created = True
            self.nodes[()] = _open(self.output,True,owned=True)
        except BaseException as error:
            error.tree_created = self.created
            self.close()
            raise

    def _verify(self,node):
        if node['handle'] is None or _snapshot(node['handle'],node['path'],node['kind']=='directory') != node['identity']:
            raise OwnershipUnknown('OUTPUT_IDENTITY_CHANGED')

    def _mkdir(self,parts):
        path = self.output.joinpath(*parts)
        if not _mkdir(_path(path),None):
            raise _error()
        self.budget.directories += 1
        return _open(path,True,owned=True)

    def _create_file(self,parts):
        node = _open(self.output.joinpath(*parts),False,owned=True,new=True)
        try:
            return node,_stream(node,True)
        except BaseException:
            self.nodes[parts] = node
            raise FileCreatedError('FILE_STREAM_OPEN_FAILED') from None

    def _list(self,node):
        buffer = ctypes.create_string_buffer(65536)
        restart = True
        while True:
            if not _query(node['handle'],11 if restart else 10,buffer,len(buffer)):
                if ctypes.get_last_error()==18:
                    return
                raise _error()
            restart = False
            offset = 0
            while True:
                info = _DirInfo.from_buffer(buffer,offset)
                start = offset+_DirInfo.name.offset
                if info.name_len%2 or start+info.name_len>len(buffer):
                    raise OwnershipUnknown('NATIVE_ENUMERATION_INVALID')
                name = buffer.raw[start:start+info.name_len].decode('utf-16-le','strict')
                if name not in ('.','..'):
                    if info.attr&0x400:
                        raise OwnershipUnknown('OUTPUT_REPARSE_POINT')
                    yield name,(node['identity'][0],info.file_id & ((1<<64)-1)),('directory' if info.attr&0x10 else 'file')
                if not info.next:
                    break
                if info.next < _DirInfo.name.offset or offset+info.next>=len(buffer):
                    raise OwnershipUnknown('NATIVE_ENUMERATION_INVALID')
                offset += info.next

    def _read_file(self,node):
        return _stream(node)

    def _remove(self,node):
        delete = w.BOOLEAN(1)
        if not _set(node['handle'],4,ctypes.byref(delete),ctypes.sizeof(delete)):
            raise _error()
        self._close_node(node)

    def _close_node(self,node):
        if node['handle'] is not None:
            if not _close(node['handle']):
                raise _error()
            node['handle'] = None
