#!/usr/bin/env python3

from cryptography.hazmat.primitives import serialization

from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError


from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.plugins.compression_plugin import CompressionScanCommand
from sslyze.plugins.fallback_scsv_plugin import FallbackScsvScanCommand 
from sslyze.plugins.heartbleed_plugin import HeartbleedScanCommand 
from sslyze.plugins.openssl_ccs_injection_plugin import OpenSslCcsInjectionScanCommand 
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand 
from sslyze.plugins.session_resumption_plugin import SessionResumptionSupportScanCommand 
from sslyze.plugins.robot_plugin import RobotScanCommand 
from sslyze.plugins.early_data_plugin import EarlyDataScanCommand 



from .. import logger
from .dbmodel import *

def create_server_info(target):
	"""
	takes SSLServer object and creates server_info 
	"""
	logger.log(1, 'create_server_info called')
	server_tester = ServerConnectivityTester(
		hostname=target.domain_name if target.domain_name is not None else target.ip_address,
		port=target.port,
		tls_wrapped_protocol=TlsWrappedProtocolEnum(target.protocol)
	)
	logger.debug(f'\nTesting connectivity with {server_tester.hostname}:{server_tester.port}...')
	try:
		server_info = server_tester.perform()
	except Exception as e:
		logger.debug('Falied to connect to server %s:%d' % (target.domain_name if target.domain_name is not None else target.ip_address, target.port))
		raise e
	return server_info

def start_scanner(session, scan_id):
	"""
	takes database session and project id, creates a scan id and start scanning for all targets belonging to project
	"""
	logger.log(1, 'create_server_info called')
	logger.debug('enumerating targets')
	
	concurrent_scanner = ConcurrentScanner()
	scan = session.query(Scan).get(scan_id)
	for target in session.query(Target).filter(scan_id == scan_id):
		try:
			server_info = create_server_info(target)
		except Exception as e:
			logger.exception('Connecting to server failed')
			tci = TargetConnectivityInfo()
			tci.scan_id = scan.id
			tci.target_id = target.id
			tci.is_connectivity_ok = False
			session.add(tci)
			session.commit()
			continue

		server_info.target_id = target.id #importent to keep track of the id fof the target!
		tci = TargetConnectivityInfo()
		tci.scan_id = scan.id
		tci.target_id = target.id
		tci.is_connectivity_ok = True
		session.add(tci)
		session.commit()

		logger.debug('Creating scan result')

		logger.debug('Enqueueing server for a scan')
		commands = []
		for res in session.query(ScanCommand.command).filter(scan_id == scan_id).distinct(ScanCommand.command).all():
			for r in res:
				commands.append(r)

		if len(commands) == 0:
			raise Exception('Scan doesnt have any commands!')
		
		for command in commands:
			for c in command_map[command]:
				concurrent_scanner.queue_scan_command(server_info, c())


	logger.debug('Starting scanner!')

	for scan_result in concurrent_scanner.get_results():
		logger.debug(f'\nReceived result for "{scan_result.scan_command.get_title()}" '
			  f'on {scan_result.server_info.hostname}')
		logger.debug('ID: %s' % scan_result.server_info.target_id)

		if isinstance(scan_result, PluginRaisedExceptionScanResult):
			logger.info('Scan command failed: %s' % scan_result.scan_command.get_title())
			f = FailedCommands()
			f.scan_id = scan.id
			f.target_id = target.id
			f.error_message = scan_result.error_message
			f.failed_command = command_map_rev[type(scan_result.scan_command)]

			session.add(f)
			session.commit()

		elif isinstance(scan_result.scan_command, CertificateInfoScanCommand):
			res = CertificateInfoScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			

			res.certificate_matches_hostname = scan_result.certificate_matches_hostname
			res.is_leaf_certificate_ev = scan_result.is_leaf_certificate_ev
			res.certificate_has_must_staple_extension = scan_result.certificate_has_must_staple_extension
			res.certificate_included_scts_count = scan_result.certificate_included_scts_count
			#ocsp_response = Column(Boolean)
			res.ocsp_response_status = scan_result.ocsp_response_status
			res.is_ocsp_response_trusted = scan_result.is_ocsp_response_trusted
			res.has_sha1_in_certificate_chain = scan_result.has_sha1_in_certificate_chain
			res.has_anchor_in_certificate_chain = scan_result.has_anchor_in_certificate_chain

			session.add(res)
			
			session.commit()
			session.refresh(res)

			idx = 0
			for certdata in scan_result.certificate_chain:
				cert = Certificate.from_result(res.id, idx, certdata.public_bytes(serialization.Encoding.PEM))
				idx += 1
				session.add(cert)
			for valres in scan_result.path_validation_result_list:
				#pvr = PathValidationResult.from_result(res.id, valres)
				ts = TrustStore.from_result(res.id, valres.trust_store)
				pvr = PathValidationResult()
				
				pvr.certificateinfoscanresult_id = res.id
				pvr.trust_store = ts
				pvr.verify_string = valres.verify_string
				pvr.is_certificate_trusted = valres.is_certificate_trusted
				
				session.add(pvr)

			for valres in scan_result.path_validation_error_list:
				pvre = PathValidationError()
				pvre.certificateinfoscanresult_id = res.id
				ts = TrustStore.from_result(res.id, valres.trust_store)
				pvre.trust_store = ts

				session.add(pvre)

			if scan_result.successful_trust_store is not None:
				ts = TrustStore.from_result(res.id, scan_result.successful_trust_store)
				res.successful_trust_store = ts

			if scan_result.path_validation_error_list is not None:
				for valres in scan_result.path_validation_error_list:
					pvre = PathValidationError.from_result(res.id, valres)
					session.add(pvre)

			session.commit()

		elif isinstance(scan_result.scan_command, (Sslv20ScanCommand, Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, Tlsv12ScanCommand, Tlsv13ScanCommand)):
			res = CipherSuiteScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			session.add(res)
			
			session.commit()
			session.refresh(res)

			for acres in scan_result.accepted_cipher_list:
				ac = AcceptedCipherSuite.from_result(acres)
				session.add(ac)
				res.accepted_cipher_list.append(ac)

			
			session.add(res)
			session.commit()


		elif isinstance(scan_result.scan_command, CompressionScanCommand):
			res = CompressionScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			#resoning for line below: documentation sais that None will be returned for compression_name
			# if no compression was set. Problem is: None is also returned in SQL when joining tables :(
			res.compression_name = scan_result.compression_name if scan_result.compression_name is not None else 'N/A'
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, FallbackScsvScanCommand):
			res = FallbackScsvScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.supports_fallback_scsv = scan_result.supports_fallback_scsv
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, HeartbleedScanCommand):
			res = HeartbleedScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.is_vulnerable_to_heartbleed = scan_result.is_vulnerable_to_heartbleed
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, OpenSslCcsInjectionScanCommand):
			res = OpenSslCcsInjectionScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.is_vulnerable_to_ccs_injection = scan_result.is_vulnerable_to_ccs_injection
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, SessionRenegotiationScanCommand):
			res = SessionRenegotiationScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.accepts_client_renegotiation = scan_result.accepts_client_renegotiation
			res.supports_secure_renegotiation = scan_result.supports_secure_renegotiation
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, SessionResumptionSupportScanCommand):
			res = SessionResumptionSupportScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.attempted_resumptions_nb = scan_result.attempted_resumptions_nb
			res.successful_resumptions_nb = scan_result.successful_resumptions_nb
			res.failed_resumptions_nb = scan_result.failed_resumptions_nb
			res.ticket_resumption_failed_reason = scan_result.ticket_resumption_failed_reason
			#res.ticket_resumption_exception = scan_result.ticket_resumption_exception
			session.add(res)
			session.commit()
			session.refresh(res)
			for errortext in scan_result.errored_resumptions_list:
				err = SessionResumptionErrors()
				err.resumption_id = res.id
				err.error = errortext
				session.add(err)
				res.errored_resumptions_list.append(err)

			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, RobotScanCommand):
			res = RobotScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.robot_result_enum = scan_result.robot_result_enum
			session.add(res)
			session.commit()

		elif isinstance(scan_result.scan_command, EarlyDataScanCommand):
			res = EarlyDataScanResult()
			res.scan_id = scan_id
			res.target_id = scan_result.server_info.target_id
			res.robot_result_enum = scan_result.is_early_data_supported
			session.add(res)
			session.commit()

	session.commit()
	session.close()
