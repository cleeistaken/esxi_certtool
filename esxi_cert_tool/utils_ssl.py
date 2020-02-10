import ssl


def unverified_ssl_context() -> ssl.SSLContext:
    """
    Create an SSLContext with host and certificate verification disabled.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
