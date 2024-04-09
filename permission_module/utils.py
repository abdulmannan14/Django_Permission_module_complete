import sys

from django.core.mail import send_mail
from django.template.loader import render_to_string

from permission_module.settings import from_email


def success_response(status_code=None, data=None, msg='Operation Success!'):
    response = {
        'success': True,
        'message': msg,
        'data': data
    }
    if status_code:
        pass
        # response["status_code"] = status_code
    return response


def failure_response(status_code=None, errors=None, msg='Operation Failure'):
    response = {
        'success': False,
        'message': msg,
        'errors': errors
    }
    if status_code:
        pass
        # response["status_code"] = status_code
    return response


def send_email(subject, context, user=None, email=None, password=None, path=None):
    # html = render_to_string(path, context)
    send_mail(
        subject if subject else "Permission",
        f'Hello {user.get_full_name()} here is your reset password verification code : {user.userprofile.verification_code}',
        from_email,
        recipient_list=[user.email, ],
        fail_silently=False
    )



def logger(message: str = "", frame=None):
    """Logs specified message.

    Args:
        message: A message to log.
        frame: A frame object from the call stack.

    See:
        https://docs.python.org/3/library/sys.html#sys._getframe
    """
    function = None
    location = None

    if frame is None:
        try:
            frame = sys._getframe()
        except:
            pass

    if frame is not None:
        try:
            previous = frame.f_back
            function = previous.f_code.co_name
            location = "%s:%s" % (
                previous.f_code.co_filename, previous.f_lineno)
        except:
            pass
    sys.stderr.write("[%s] [%s] %s\r\n" %
                     (function, location, message))

