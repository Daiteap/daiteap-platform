
class mockClass:
    pass

def func_with_exception(*arg):
    raise Exception('Mocked Exception')

def func_returns_false(*arg):
    return False

def func_returns_none(*arg):
    return None

def func_no_return(*arg):
    return

def func_returns_number(*arg):
    return 123


def func_worker_validate_credentials(*arg):
    mock = mockClass
    mock.id = '123-456-789'
    return mock

def func_return_list(*arg):
    return ['test1', 'test2']
