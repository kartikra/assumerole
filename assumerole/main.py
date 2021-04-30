import argparse
from assumerole import identity


def app():

    # Initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", help="aws profile name to assume")
    parser.add_argument("-r", "--refresh", help="discard cache and get fresh token", action="store_true")
    parser.add_argument("-d", "--duration", help="when should the token expire (default 8 hours). Max 12 hours",
                        default=8)

    # Read arguments from the command line. Note args.refresh defaults to False when not specified
    args = parser.parse_args()
    os_env, command = identity.assume_role(args.profile, args.refresh, args.duration)
    print(command)


if __name__ == "__main__":
    app()
