from .policy import *
def authorize(result):
    if not result.ok:
        raise PermissionError(result.reason)