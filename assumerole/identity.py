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


def set_profile(config, aws_profile_name, expire_duration_hours=8):

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

    variable_mapping = dict()
    variable_mapping["AWS_ACCESS_KEY_ID"] = "AccessKeyId"
    variable_mapping["AWS_SECRET_ACCESS_KEY"] = "SecretAccessKey"
    variable_mapping["AWS_SESSION_TOKEN"] = "SessionToken"
    variable_mapping["AWS_SECURITY_TOKEN"] = "SessionToken"

    if cached_config != {} and cached_config.get("Credentials", {}) != {}:
        cached_credentials = cached_config["Credentials"]

        for target, source in variable_mapping.items():
            my_env[target] = cached_credentials.get(source, "")
        my_env['ASSUMED_ROLE'] = aws_profile_name

        set_cmd = list()
        for target, source in variable_mapping.items():
            set_cmd.append("unset {0}".format(target))
            set_cmd.append("export {0}=\"{1}\"".format(target, cached_credentials.get(source, "")))

        set_cmd.append("unset ASSUMED_ROLE")
        set_cmd.append("export ASSUMED_ROLE='{0}'".format(aws_profile_name))

        set_command = ';'.join(set_cmd)

    return my_env, set_command


def assume_role(aws_profile_name, force_refresh=False, expire_duration_hours=8):

    config = check_aws_config_file()
    os_env = os.environ.copy()
    command = ""

    if config is not None:
        if check_cached_token(aws_profile_name) or force_refresh:
            if not set_profile(config, aws_profile_name, expire_duration_hours):
                return os_env, command

        os_env, command = set_cached_token(aws_profile_name)
        os.environ = os_env

    return os_env, command
