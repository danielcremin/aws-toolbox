import requests
import json
import ipaddress
import argparse


class AWSIPChecker:

    def __init__(self):

        self.AWS_IP_RANGES = 'https://ip-ranges.amazonaws.com/ip-ranges.json'

    def check_valid_ip(self, ip_address) -> bool:

        """Checks the provided IP a valid IPv4 address

           :param: ip_addr: An IPv4 address
           :return: bool: True if IPv4, false if not a valid IPv4"""

        try:
            ip_address = ipaddress.IPv4Address(ip_address)
            return True

        except ipaddress.AddressValueError as e:
            print('[Error] - {}'.format(e))
            return False

    def get_aws_ip_ranges(self) -> list:

        """Retrieves a list of the AWS IP Ranges

           :return: list: AWS IP Ranges"""

        try:
            r = requests.get(self.AWS_IP_RANGES)

            if r.ok:
                r = json.loads(r.text)
                return r['prefixes']
            else:
                print('[Error] - Response code: {}'.format(r.status_code))

        except requests.exceptions.RequestException as e:
            print('[Error] -'.format(e))

    def check_ip_in_aws_ranges(self, ip_address, aws_ip_ranges) -> bool and str:

        """Checks if the IP exists within AWS' IP ranges

           :param: ip_addr: A valid IPv4 address
           :param: aws_ip_ranges: A list of AWS' IP ranges
           :return: Bool & str/None"""

        ip_address = ipaddress.IPv4Address(ip_address)  # Converts to IPv4Address object

        for prefix in aws_ip_ranges:
            aws_network = ipaddress.IPv4Network(prefix["ip_prefix"], strict=False)

            if ip_address in aws_network:
                return True, prefix

        return False, None

    def app(self, ip_address) -> dict:

        if self.check_valid_ip(ip_address):

            aws_ip_ranges = self.get_aws_ip_ranges()

            outcome, prefix = self.check_ip_in_aws_ranges(ip_address, aws_ip_ranges)

            if outcome:
                ip_details = {'aws_owned': True, 'prefix': prefix['ip_prefix'],
                              'region': prefix['region'], 'service': prefix['service']}

            else:
                ip_details = {'aws_owned': False}

            return ip_details


def main():

    """This scripts enumerates the AWS IP ranges JSON file, checking if a
       provided IPv4 address is part of the AWS IP range.

       An ip_details dictionary is returned indicating if AWS owns the IP,
       with additional details provided such as the region of the IP if it
       is owned by AWS.

      This is script can be used standalone or as an import to another project.

      ** Examples **

      Usage 1: python aws_ip_checker.py 54.169.123.103
      Return: {'aws_owned': True, 'prefix': '54.169.0.0/16', 'region': 'ap-southeast-1', 'service': 'AMAZON'}

      Usage 2: python aws_ip_checker.py 10.10.10.10
      Return: {'aws_owned': False}

     Author: https://github.com/danielcremin"""

    parser = argparse.ArgumentParser(description='AWS IP Checker - Checks if a IPv4 address is owned by AWS')
    parser.add_argument("ip_address", help="The IPv4 address to check")
    args = parser.parse_args()
    ip_address = args.ip_address

    aipc = AWSIPChecker()
    print(aipc.app(ip_address=ip_address))


if __name__ == "__main__":
    main()

