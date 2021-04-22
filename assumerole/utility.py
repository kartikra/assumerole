import configparser
import os
import boto3
import json
import time
import botocore.exceptions
from botocore.session import Session


def check_aws_config_file():

    config = None
    aws_config_file = os.environ['HOME'] + "/.aws/config"
    if os.path.isdir(os.environ['HOME'] + "/.aws"):
        if os.path.isfile(aws_config_file):
            config = configparser.ConfigParser()
            config.read(aws_config_file)

            if not os.path.isdir(os.environ['HOME'] + "/.aws/cached_tokens"):   # pragma: no cover
                os.makedirs(os.environ['HOME'] + "/.aws/cached_tokens")
        else:   # pragma: no cover
            print(aws_config_file + " not found. Exiting")
    else:   # pragma: no cover
        print("~/.aws folder not found. Exiting")

    return config


def run_assume_role(config, aws_profile_name, expire_duration_hours=8):

    list_aws_profile = config.sections()
    if "profile " + aws_profile_name in list_aws_profile:

        session = "dev"
        aws_config = Session(profile=aws_profile_name).get_scoped_config()

        # Construct assume role request
        assert "role_arn" in aws_config, f"{aws_profile_name} does not have role_arn."
        rq = {
            "RoleArn": aws_config["role_arn"],
            "RoleSessionName": session,
            "DurationSeconds": (expire_duration_hours*3600)
        }
        expire_time = int(time.time()) + (expire_duration_hours*3600)
        # Add MFA token if needed
        if "mfa_serial" in aws_config:  # pragma: no cover
            print("\n Enter MFA Code:")
            mfa_code = input()
            rq["SerialNumber"] = aws_config["mfa_serial"]
            rq["TokenCode"] = mfa_code

        # Get auth token
        try:
            sts = boto3.client("sts")
            sts_response = sts.assume_role(**rq)
            sts_response['Credentials']["Expiration"] = expire_time

            cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
            with open(cached_folder + "/" + aws_profile_name + ".txt", "w") as fp:
                fp.write(json.dumps(sts_response))
                fp.close()
            assume_role_status = True

        except botocore.exceptions.ClientError as ex:
            print(ex.response)
            print("\nProfile {0} not set correctly. Please retry with correct credentials\n".format(aws_profile_name))
            assume_role_status = False

    else:
        print("aws profile not found\n")
        assume_role_status = False

    return assume_role_status


def check_cached_token(aws_profile_name):

    cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
    aws_cached_file = cached_folder + "/" + aws_profile_name + ".txt"

    if os.path.isfile(aws_cached_file):
        with open(aws_cached_file, "r") as fp:
            cached_string = fp.read()
            fp.close()
        try:
            cached_config = json.loads(cached_string)
        except json.decoder.JSONDecodeError:    # pragma: no cover
            cached_config = {}
    else:
        cached_config = {}

    expiration = cached_config.get("Credentials", {}).get("Expiration", -1)
    if expiration != -1:
        if int(time.time()) <= expiration:
            token_expired = False
        else:   # pragma: no cover
            token_expired = True
    else:   # pragma: no cover
        token_expired = True

    return token_expired


def set_cached_token(aws_profile_name):

    cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
    aws_cached_file = cached_folder + "/" + aws_profile_name + ".txt"

    if os.path.isfile(aws_cached_file):
        with open(aws_cached_file, "r") as fp:
            cached_string = fp.read()
            fp.close()

        try:
            cached_config = json.loads(cached_string)
        except json.decoder.JSONDecodeError:    # pragma: no cover
            cached_config = {}
    else:
        cached_config = {}

    my_env = os.environ.copy()
    set_command = ""

    if cached_config != {}:
        my_env['AWS_ACCESS_KEY_ID'] = cached_config.get("Credentials", {}).get("AccessKeyId", "")
        my_env['AWS_SECRET_ACCESS_KEY'] = cached_config.get("Credentials", {}).get("SecretAccessKey", "")
        my_env['AWS_SESSION_TOKEN'] = cached_config.get("Credentials", {}).get("SessionToken", "")
        my_env['AWS_SECURITY_TOKEN'] = cached_config.get("Credentials", {}).get("SessionToken", "")
        my_env['ASSUMED_ROLE'] = aws_profile_name

        set_cmd = list()
        set_cmd.append("unset AWS_ACCESS_KEY_ID")
        set_cmd.append("unset AWS_SECRET_ACCESS_KEY")
        set_cmd.append("unset AWS_SESSION_TOKEN")
        set_cmd.append("unset AWS_SECURITY_TOKEN")
        set_cmd.append("unset ASSUMED_ROLE")
        set_cmd.append("export AWS_ACCESS_KEY_ID=\"{0}\"".format(cached_config.get("Credentials", {}).get("AccessKeyId", "")))
        set_cmd.append("export AWS_SECRET_ACCESS_KEY='{0}'".format(cached_config.get("Credentials", {}).get("SecretAccessKey", "")))
        set_cmd.append("export AWS_SESSION_TOKEN='{0}'".format(cached_config.get("Credentials", {}).get("SessionToken", "")))
        set_cmd.append("export AWS_SECURITY_TOKEN='{0}'".format(cached_config.get("Credentials", {}).get("SessionToken", "")))
        set_cmd.append("export ASSUMED_ROLE='{0}'".format(aws_profile_name))
        set_command = ';'.join(set_cmd)

    return my_env, set_command


def set_profile(aws_profile_name, force_refresh=False, expire_duration_hours=12):

    config = check_aws_config_file()
    os_env = os.environ.copy()
    command = ""

    if config is not None:
        if check_cached_token(aws_profile_name) or force_refresh:
            if not run_assume_role(config, aws_profile_name, expire_duration_hours):
                return os_env, command

        os_env, command = set_cached_token(aws_profile_name)
        os.environ = os_env

    return os_env, command



