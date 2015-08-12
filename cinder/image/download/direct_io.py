import mmap
import os
import time
import hashlib
from cinder.i18n import _
import logging

LOG = logging.getLogger(__name__)

def write(filename, data, chunk_size=1024 * 1024):
    """
    Write the data into a file in the way of DirectIO.
    
    filename  : destination file name
    data      : data to write to filename, must be chunkable
    chunk_size: size of data returned by data each time. must be several times of 4K
    """
    LOG.debug(_('start write file %(dst_file)s using direct io mode') %
              {'dst_file': filename})
    try:
        fp = os.open(filename, os.O_WRONLY|os.O_DIRECT|os.O_CREAT)
        m = mmap.mmap(-1, chunk_size)

        # Firstly, write most chunks with direct IO method.
        tail = ''
        size = 0
        for chunk in data:
            c_size = len(chunk)
            free_size = chunk_size - size % chunk_size
            size += c_size
            if c_size < free_size:
                m.write(chunk)
            else:
                m.write(chunk[:free_size])
                writed_size = free_size
                os.write(fp, m)
                m.seek(0)
                while (c_size - writed_size) / chunk_size:
                    m.write(chunk[writed_size:writed_size + chunk_size])
                    os.write(fp, m)
                    m.seek(0)
                    writed_size += chunk_size
                m.write(chunk[writed_size:])

            #sleep to let in other green-thread tasks
            time.sleep(0)
    finally:
        m.seek(0)
        tail = m.read(size % chunk_size)
        if 'fp' in locals():
            os.close(fp)
        if 'm' in locals():
            m.close()

    # Then, add the last chunk with ordinary method.
    if tail:
        with open(filename, "a") as f:
            f.write(tail)
    LOG.debug('write file :%s successfully, the size is :%s' % (filename, size))
    return size
