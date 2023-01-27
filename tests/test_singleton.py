from src.util.singleton import Singleton


def test_singleton():
    class SingletonObject(metaclass=Singleton):
        def __init__(self):
            pass

    a = SingletonObject()
    b = SingletonObject()
    assert a is b
