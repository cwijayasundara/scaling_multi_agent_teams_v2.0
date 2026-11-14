"""Optional immutable external decision archive using S3 Object Lock.

Bucket provisioning and IAM policy belong to the operator. No credentials are
forwarded to guests or models. No bucket or retention policy is created here.
DirectoryArchive is a local exclusive-create stand-in for service tests. It does
not provide Object Lock, IAM or cloud immutability.
"""
import base64
import hashlib
import os
import re
from datetime import datetime,timedelta,timezone
from pathlib import Path

from .analytics import canonical,digest
from .security import SecurityError


class S3Archive:
    def __init__(self, client, bucket, days=30):
        if not isinstance(bucket,str) or not 3<=len(bucket)<=63 or not 1<=days<=3650:
            raise ValueError('valid bucket and 1..3650 retention days required')
        self.client,self.bucket,self.days=client,bucket,days

    def preflight(self):
        try:
            config=self.client.get_object_lock_configuration(Bucket=self.bucket)['ObjectLockConfiguration']
            if config.get('ObjectLockEnabled')!='Enabled':
                raise SecurityError('audit bucket must have Object Lock enabled')
        except Exception as exc:
            raise SecurityError('immutable audit archive preflight failed') from exc

    def append(self,record):
        data=canonical(record).encode()
        try:
            result=self.client.put_object(Bucket=self.bucket,
                Key='decisions/'+record['run_id']+'/'+record['operation_id']+'-'+digest(record)+'.json',
                Body=data,ContentType='application/json',IfNoneMatch='*',
                ChecksumSHA256=base64.b64encode(hashlib.sha256(data).digest()).decode(),
                ObjectLockMode='COMPLIANCE',ObjectLockRetainUntilDate=datetime.now(timezone.utc)+timedelta(days=self.days),
                ServerSideEncryption='AES256')
            if not result.get('VersionId'):
                raise OSError('versioned archive receipt missing')
        except Exception as exc:
            raise OSError('immutable audit archive write failed') from exc


class DirectoryArchive:
    def __init__(self, root, days=30):
        if not 1 <= days <= 3650:
            raise ValueError('retention days must be 1..3650')
        self.root, self.days = Path(root), days

    def preflight(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        if self.root.is_symlink() or not self.root.is_dir() or self.root.stat().st_mode & 0o077:
            raise SecurityError('private archive directory required')

    def append(self, record):
        data = canonical(record).encode()
        name = record['run_id'] + '/' + record['operation_id'] + '-' + digest(record) + '.json'
        if not re.fullmatch(r'[0-9a-f]{24}/[0-9a-f]{32}-[0-9a-f]{64}\.json', name):
            raise SecurityError('archive key rejected')
        target = self.root / 'decisions' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400)
        except FileExistsError as exc:
            raise OSError('immutable audit archive write failed') from exc
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        until = datetime.now(timezone.utc) + timedelta(days=self.days)
        target.with_name(target.name + '.retention').write_text(until.isoformat())
        if not target.stat().st_size:
            raise OSError('versioned archive receipt missing')


def configured_archive(bucket, days=30, endpoint=None):
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise ValueError('external archive requires the audit optional dependency') from exc
    if endpoint and not (endpoint.startswith('https://') or endpoint.startswith('http://127.0.0.1') or endpoint.startswith('http://localhost')):
        raise ValueError('audit endpoint must be https or a loopback http endpoint')
    config = Config(connect_timeout=3, read_timeout=5, retries={'max_attempts': 0}, s3={'addressing_style': 'path'})
    kwargs = {'config': config}
    if endpoint:
        kwargs['endpoint_url'] = endpoint
    client = boto3.client('s3', **kwargs)
    archive = S3Archive(client, bucket, days)
    archive.preflight()
    return archive
