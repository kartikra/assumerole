import argparse
import assumerole.utility as util


def app():

    # Initiate the parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", help="aws profile name to assume")
    parser.add_argument("-r", "--refresh", help="discard cache and get fresh token", action="store_true")

    # Read arguments from the command line. Note args.refresh defaults to False when not specified
    args = parser.parse_args()
    os_env, command = util.assume_role_wrapper(args.profile, args.refresh)
    print(command)


if __name__ == "__main__":
    app()
