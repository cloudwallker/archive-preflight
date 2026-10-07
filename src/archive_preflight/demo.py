"""Deterministic original ZIP demonstrations; metadata reports use the real engine."""
from io import BytesIO
import zipfile


def synthetic_zip(entries):
    output=BytesIO()
    with zipfile.ZipFile(output,'w') as archive:
        for name,data,kind,method in entries:
            info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.create_system=3
            info.external_attr=(0o120600 if kind=='symlink' else 0o40700 if kind=='directory' else 0o100600)<<16
            if kind=='directory':info.external_attr|=0x10
            info.compress_type=method
            archive.writestr(info,data)
    return output.getvalue()


def eight_risks_zip():
    entries=[(name,b'Original synthetic content.\n','file',0) for name in
             ('Report.txt','report.txt','CON.txt','tail.','caf\u00e9.txt','cafe\u0301.txt','/'.join(['segment']*27)+'/deep.txt','../escape.txt')]
    entries.extend([('link',b'outside.txt','symlink',0),('ratio.txt',b'A'*131072,'file',8)])
    return synthetic_zip(entries)
