import argparse


def hash(str):
    hash = 0x0
    for c in str:
        hash = ord(c) + ((hash >> 10) | (hash << 8))
        hash = hash & 0xffffffff
    return (hash)

def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('--str', type=str, required=True, )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse()

    print(hex(hash(args.str)).upper())

