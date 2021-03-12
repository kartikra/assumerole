import configparser
import os
from subprocess import Popen, PIPE
import json
import datetime
import time


def call_sub_process(command):

    process = Popen(['/bin/bash', '-c', command], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()

    results = stdout.decode('utf-8')
    error_message = stderr.decode('utf-8')

    return results, error_message


def check_aws_config_file():

    config = None
    aws_config_file = os.environ['HOME'] + "/.aws/config"
    if os.path.isdir(os.environ['HOME'] + "/.aws"):
        if os.path.isfile(aws_config_file):
            config = configparser.ConfigParser()
            config.read(aws_config_file)

            if not os.path.isdir(os.environ['HOME'] + "/.aws/cached_tokens"):
                os.makedirs(os.environ['HOME'] + "/.aws/cached_tokens")
        else:
            print(aws_config_file + " not found. Exiting")
    else:
        print("~/.aws folder not found. Exiting")

    return config


def run_assume_role(config, aws_profile_name):

    history_file = os.environ['HOME'] + "/.aws/assume_role_history"

    list_aws_profile = config.sections()
    if "profile " + aws_profile_name in list_aws_profile:
        aws_profile_config = config["profile " + aws_profile_name]
        role_arn = aws_profile_config.get("role_arn", "")
        external_id = aws_profile_config.get("external_id", "")
        mfa_serial = aws_profile_config.get("mfa_serial", "")
        session = "dev"

        command = "aws sts assume-role --role-session-name {session}".format(mfa_serial=mfa_serial, session=session)

        if role_arn != "":
            command += " --role-arn {0}".format(role_arn)

        if mfa_serial != "":
            command += " --serial-number {0}".format(mfa_serial)

        if external_id != "":
            command += " --external-id {0}".format(external_id)

        stdout, error_message = call_sub_process(command)

        while error_message != "":
            print(error_message)
            print("\n Enter MFA Code:")
            mfa_code = input()
            command_with_mfa = command + " --token-code " + mfa_code
            stdout, error_message = call_sub_process(command_with_mfa)

        cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
        with open(cached_folder + "/" + aws_profile_name + ".txt", "w") as fp:
            fp.write(stdout)
            fp.close()

        with open(history_file, 'a') as ap:
            ap.write("\n" + aws_profile_name + "\n")
            ap.write(command + "\n")
            ap.close()

    else:
        print("aws profile not found")

    return


def check_cached_token(aws_profile_name):

    cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
    aws_cached_file = cached_folder + "/" + aws_profile_name + ".txt"

    if os.path.isfile(aws_cached_file):
        with open(aws_cached_file, "r") as fp:
            cached_string = fp.read()
            fp.close()
        cached_config = json.loads(cached_string)
    else:
        cached_config = {}

    expiration = cached_config.get("Credentials", {}).get("Expiration", "")
    if expiration != "":
        if expiration.find("+") > -1:
            new_expiration = expiration.split("+")[0]
            expire_ts = time.mktime(datetime.datetime.strptime(new_expiration,
                                                               "%Y-%m-%dT%H:%M:%S").timetuple())
        else:
            new_expiration = expiration
            expire_ts = time.mktime(datetime.datetime.strptime(new_expiration,
                                                               "%Y-%m-%dT%H:%M:%SZ").timetuple())
        utc_time = datetime.datetime.utcnow()
        current_ts = utc_time.timestamp()
        if round(current_ts) <= round(expire_ts):
            token_expired = False
        else:
            token_expired = True
    else:
        token_expired = True

    return token_expired


def set_cached_token(aws_profile_name):

    cached_folder = os.environ['HOME'] + "/.aws/cached_tokens"
    aws_cached_file = cached_folder + "/" + aws_profile_name + ".txt"

    if os.path.isfile(aws_cached_file):
        with open(aws_cached_file, "r") as fp:
            cached_string = fp.read()
            fp.close()
        cached_config = json.loads(cached_string)
    else:
        cached_config = {}

    my_env = os.environ.copy()
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


def assume_role_wrapper(aws_profile_name, force_refresh=False):

    config = check_aws_config_file()
    os_env = os.environ.copy()
    command = ""

    if config is not None:
        if check_cached_token(aws_profile_name) or force_refresh:
            run_assume_role(config, aws_profile_name)
        os_env, command = set_cached_token(aws_profile_name)

    return os_env, command
