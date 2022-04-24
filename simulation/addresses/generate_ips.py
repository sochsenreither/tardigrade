import sys

def print_ips(n):
    step = n/4
    c = 0
    l = 0

    ips = ["52.90.96.134", "54.219.159.220", "13.215.202.237", "13.48.130.17"]

    print("{")
    print(f"\"{-1}\": \"{ips[3]}:4321\",")

    for i in range(n):
        if l >= step:
            c += 1
            l = 0
        port = "123" + str(i)
        if int(port) > 65000:
            port = "22" + str(i)
        l += 1
        if i == n-1:
            print(f"\"{i}\": \"{str(ips[c])}:{port}\"")
        else:
            print(f"\"{i}\": \"{str(ips[c])}:{port}\",")

    print("}")

print_ips(int(sys.argv[1]))
