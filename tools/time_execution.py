import time

TIMES = 1000


def time_exec(func):
    def wrapper(plaintext, key, show):
        if not show:
            start = time.time()
            for i in range(TIMES):
                func(plaintext=plaintext, key=key, show=show)
            end = time.time()
            print(f'{func.__name__}: {TIMES} times works {end - start}s')
        func(plaintext, key, show)

    return wrapper
