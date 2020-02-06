import progressbar
import subprocess

from time import sleep


def ping(hostname: str) -> bool:
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.

    Ref.
    https://stackoverflow.com/questions/28769023/get-output-of-system-ping-without-printing-to-the-console
    https://docs.python.org/3/library/subprocess.html
    """
    try:
        cmd = ['ping', '-c', '1', '-W', '1', hostname]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def host_down(hostname: str, max_tries: int = 300):
    required_consecutive = 5
    consecutive = required_consecutive
    with progressbar.ProgressBar(max_value=max_tries) as bar:
        for i in range(max_tries):
            bar.update(i)
            sleep(1)
            status = ping(hostname)
            if not status:  # wait for host NOT to respond
                consecutive -= 1
            else:
                consecutive = required_consecutive
            if consecutive < 1:
                return
    raise RuntimeError(f'Host still responding after {max_tries} seconds')


def host_up(hostname: str, max_tries: int = 300):
    required_consecutive = 5
    consecutive = required_consecutive
    with progressbar.ProgressBar(max_value=max_tries) as bar:
        for i in range(max_tries):
            bar.update(i)
            sleep(1)
            status = ping(hostname)
            if status:  # wait for host to respond
                consecutive -= 1
            else:
                consecutive = required_consecutive
            if consecutive < 1:
                return
    raise RuntimeError(f'Host not responding after after {max_tries} seconds')