#!/usr/bin/env python3

#
# check user input
#
import sys
if not (len(sys.argv) > 1 and sys.argv[1].isdigit()):
    print('Usage: scan.py <rate> <country1> <country2>... <countryN>')
    print('Example: scan.py 2000 hk')
    print('This will scan all the Hong Kong ips at the speed of 2000 pps')
    exit(1)

#
# get the latest the cidr list of target countries/regions
#
from utils.web_ops import IPRangeGrabber

countries = sys.argv[2:]
countries = list(map(lambda string: string.upper(), countries))
cidr = IPRangeGrabber(countries)

#
# run masscan
#
import datetime
import os
param_rate = sys.argv[1]
now = datetime.datetime.now()
cur_time = now.strftime('%Y-%m-%d-%H-%M-%S')
param_scan_result_filename = 'scan_result/{}-{}.log'.format(
    '_'.join(countries), cur_time)
param_cidrs = ' '.join(cidr.collection)
# print('masscan -c masscan.conf --range {0} --output-file {1} --rate {2}'.format(
    # param_cidrs, param_scan_result_filename, param_rate))
cur_folder = os.path.dirname(os.path.realpath(__file__))
masscan_folder = cur_folder + '/masscan/bin'
print('{0}/masscan -c masscan.conf --range {1} --output-file {2} --rate {3}'.format(masscan_folder,param_cidrs, param_scan_result_filename, param_rate))
# os.system('{}/masscan -c masscan.conf --range {0} --output-file {1} --rate {2}'.format(masscan_folder,param_cidrs, param_scan_result_filename, param_rate))

#
# parse the log
#
from utils.log_ops import LogReader
masscan_log = LogReader(param_scan_result_filename)
with open('scan_result/{}-{}.ip.txt'.format('_'.join(countries), cur_time), 'w') as f:
    f.write('#gvs' + os.linesep)
    f.write('|'.join(masscan_log.gvs_pool) + os.linesep)
    f.write('#gws' + os.linesep)
    f.write('|'.join(masscan_log.gws_pool) + os.linesep)
