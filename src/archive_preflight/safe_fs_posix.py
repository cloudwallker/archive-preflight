"""POSIX dir_fd backend. Native execution evidence must be recorded per platform."""
import os
import stat

from .safe_fs import _Tree, OwnershipUnknown, UnsupportedHost, FileCreatedError, checked_parts


def _identity(info):
    return info.st_dev,info.st_ino


class PosixTree(_Tree):
    backend = 'posix-dir-fd-native'

    def __init__(self,output):
        self._initialize(output)
        required = (os.open,os.mkdir,os.stat,os.unlink,os.rmdir)
        if not all(fn in os.supports_dir_fd for fn in required) or os.listdir not in os.supports_fd or not hasattr(os,'O_NOFOLLOW'):
            raise UnsupportedHost('DIR_FD_UNAVAILABLE')
        checked_parts((self.output.name,))
        try:
            node = self._node(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW),None,'/',True)
            self.ancestors.append(node)
            for name in self.output.parts[1:-1]:
                node = self._open_dir(node['fd'],name)
                self.ancestors.append(node)
            os.mkdir(self.output.name,0o700,dir_fd=node['fd'])
            self.created = True
            self.nodes[()] = self._open_dir(node['fd'],self.output.name)
        except BaseException as error:
            error.tree_created = self.created
            self.close()
            raise

    def _node(self,fd,parent,name,directory):
        try:
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode)) or (not directory and info.st_nlink!=1):
                raise OwnershipUnknown('OUTPUT_TYPE_CHANGED')
            return {'fd':fd,'parent':parent,'name':name,'identity':_identity(info),'kind':'directory' if directory else 'file'}
        except BaseException:
            os.close(fd)
            raise

    def _open_dir(self,parent,name):
        return self._node(os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent),parent,name,True)

    def _verify(self,node):
        if node['fd'] is None:
            raise OwnershipUnknown('CLOSED_HANDLES')
        info = os.fstat(node['fd'])
        path_info = os.stat(node['name'],dir_fd=node['parent'],follow_symlinks=False)
        directory = node['kind']=='directory'
        if (_identity(info)!=node['identity'] or _identity(path_info)!=node['identity']
                or (not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
                or (not directory and info.st_nlink!=1)):
            raise OwnershipUnknown('OUTPUT_IDENTITY_CHANGED')

    def _mkdir(self,parts):
        parent = self.nodes[parts[:-1]]['fd']
        os.mkdir(parts[-1],0o700,dir_fd=parent)
        self.budget.directories += 1
        return self._open_dir(parent,parts[-1])

    def _create_file(self,parts):
        parent = self.nodes[parts[:-1]]['fd']
        fd = os.open(parts[-1],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
        try:
            node = self._node(fd,parent,parts[-1],False)
        except BaseException:
            raise FileCreatedError('FILE_IDENTITY_UNVERIFIED') from None
        try:
            return node,os.fdopen(os.dup(fd),'r+b',buffering=0)
        except BaseException:
            self.nodes[parts] = node
            raise FileCreatedError('FILE_STREAM_OPEN_FAILED') from None

    def _list(self,node):
        for name in os.listdir(node['fd']):
            info = os.stat(name,dir_fd=node['fd'],follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise OwnershipUnknown('OUTPUT_TYPE_CHANGED')
            yield name,_identity(info),'directory' if stat.S_ISDIR(info.st_mode) else 'file'

    def _read_file(self,node):
        result = os.fdopen(os.dup(node['fd']),'rb',buffering=0)
        result.seek(0)
        return result

    def _remove(self,node):
        operation = os.rmdir if node['kind']=='directory' else os.unlink
        operation(node['name'],dir_fd=node['parent'])
        self._close_node(node)

    def _close_node(self,node):
        if node['fd'] is not None:
            os.close(node['fd'])
            node['fd'] = None
