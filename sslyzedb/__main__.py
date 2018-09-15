#!/usr/bin/env python3

import logging
import csv
import os
import sys
import ipaddress

from sslyzedb.core.dbmodel import Project, Scan, Target, get_session, create_db
from sslyzedb.core.scanner import *
from sslyzedb.core.report import *
from sslyzedb.utils import *
from sslyzedb import logger

def get_connection_string(args):
	if args.sql is not None and args.sql != '':
		return args.sql
	if 'SSLYZEDB' in os.environ:
		return os.environ['SSLYZEDB']
	else:
		raise Exception('DB connection string missing! Provide if either via the "--sql" parameter or by setting the "SSLYZEDB" environment variable')

def run():
	import argparse
	parser = argparse.ArgumentParser(description='SSLZye on DB')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--sql', help='sql engine address, if not present the script will look for the "SSLYZEDB" environment variable')
	
	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'command'

	db_group = subparsers.add_parser('db', help='Database operations')
	db_group.add_argument('cmd', nargs='?', choices=['create'], help='Database commands.')
	db_group.add_argument('rest', nargs=argparse.REMAINDER)

	createproject_group = subparsers.add_parser('createproject', help='Creates project and gives back the project id')
	createproject_group.add_argument('name', help='Project name')

	createscan_group = subparsers.add_parser('createscan', help='Creates a new scan and adds targets')
	createscan_group.add_argument('projectid', help='Project id that defines the scope')

	addtarget_group = subparsers.add_parser('addtarget', help='Adds target(s) to scan id')
	addtarget_group.add_argument('scanid', help='Project id that defines the scope')
	addtarget_group.add_argument('source', nargs='?', choices=['file', 'stdin'], help='Database commands.')
	addtarget_group.add_argument('rest', nargs=argparse.REMAINDER)

	addcmd_group = subparsers.add_parser('addcommand', help='Adds command(s) to scan id')
	addcmd_group.add_argument('scanid', help='Project id that defines the scope')
	addcmd_group.add_argument('commands', nargs=argparse.REMAINDER, help='Scan commands')

	scan_group = subparsers.add_parser('scan', help='Start scanning')
	scan_group.add_argument('scanid', help='Scan id that defines the scope')

	report_group = subparsers.add_parser('report', help='Generate report')
	report_group.add_argument('scanid', help='Scan id that defines the scope')
	report_group.add_argument('-o', '--outfile', help='File to write the report to, otherwise STDOUT')

	args = parser.parse_args()
	
	
	###### VERBOSITY
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
		logger.setLevel(logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
		logger.setLevel(logging.DEBUG)
	else:
		logging.basicConfig(level=1)
		logger.setLevel(1)

	if args.command == 'db':
		if args.cmd == 'create':
			conn = get_connection_string(args)
			create_db(conn, args.verbose)

		else:
			raise Exception('Unsupported DB subcommand %s' % args.cmd)

	elif args.command == 'createproject':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		logging.debug('Creating project')
		project = Project(args.name,'')
		session.add(project)
		session.commit()
		session.refresh(project)
		session.close()
		logging.info('Created project with ID %s' % project.id)

	elif args.command == 'createscan':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		logging.debug('Creating scan')
		project = session.query(Project).get(args.projectid)
		scan = Scan()
		session.add(scan)
		session.commit()
		session.refresh(scan)
		session.close()
		logging.debug('Created scan with ID %s' % scan.id)

	elif args.command == 'addtarget':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		scan = session.query(Scan).get(args.scanid)
		if args.source == 'file':
			try:
				for filename in args.rest:
					with open(filename, 'r') as f:
						for line in f:
							line = line.strip()
							target = Target.from_line(line)
							scan.targets.append(target)

			except Exception as e:
				logging.exception('Failed to parse targets file!')
				sys.exit()
			

		else:
			for targetentry in args.rest:
				target = Target.from_line(targetentry)
				scan.targets.append(target)
		session.add(scan)
		session.commit()
		session.close()

	elif args.command == 'addcommand':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		scan = session.query(Scan).get(args.scanid)
		for command in args.commands:
			c = SSLYZECommand[command.upper()]
			sc = ScanCommand()
			sc.scan_id = args.scanid
			sc.command = c
			session.add(sc)

		session.commit()
		session.close()
		logging.debug('Commands added')

	elif args.command == 'scan':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		logging.debug('Starting scan')

		start_scanner(session, args.scanid)

	elif args.command == 'report':
		conn = get_connection_string(args)
		session = get_session(conn, args.verbose)
		logging.debug('Starting reporting')
		data_lines = generate_report(session, args.scanid)
		if args.outfile is not None:
			with open(args.outfile,'wb') as f:
				for line in data_lines:
					f.write('\t'.join(line).encode() + b'\r\n')
		else:
			for line in data_lines:
				print('\t'.join(line))

if __name__ == '__main__':
	run()