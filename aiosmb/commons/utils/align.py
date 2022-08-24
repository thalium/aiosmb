def align(n, a):
    return (n + (a-1)) & (~(a-1))
