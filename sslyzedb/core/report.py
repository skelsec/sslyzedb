from collections import OrderedDict
from nassl.ssl_client import OpenSslVersionEnum

from sqlalchemy import and_

from .. import logger
from ..utils import *
from .dbmodel import *

class FullResult:
	HEADER = ['target','compression_supported','supports_fallback_scsv', 'is_vulnerable_to_heartbleed',  'is_vulnerable_to_ccs_injection', \
				'accepts_client_renegotiation', 'supports_secure_renegotiation', 'robot_result', 'is_early_data_supported', 'SSLV23', \
				'SSLV2','SSLV3','TLSV1', 'TLSV1_1', 'TLSV1_2', 'TLSV1_3'
				]
				
	HEADER_FULL = ['target','compression_supported','supports_fallback_scsv', 'is_vulnerable_to_heartbleed',  'is_vulnerable_to_ccs_injection', \
				'accepts_client_renegotiation', 'supports_secure_renegotiation', 'robot_result', 'is_early_data_supported', 'SSLV23', \
				'SSLV2','SSLV3','TLSV1', 'TLSV1_1', 'TLSV1_2', 'TLSV1_3', 'SSLV23_accepted_ciphers', 'SSLV2_accepted_ciphers','SSLV3_accepted_ciphers',\
				'TLSV1_accepted_ciphers', 'TLSV1_1_accepted_ciphers', 'TLSV1_2_accepted_ciphers', 'TLSV1_3_accepted_ciphers'
				]


	def __init__(self):
		self.target = None
		self.compression_supported = None
		self.supports_fallback_scsv = None
		self.is_vulnerable_to_heartbleed = None
		self.is_vulnerable_to_ccs_injection = None
		self.accepts_client_renegotiation = None
		self.supports_secure_renegotiation = None
		self.robot_result = None
		self.is_early_data_supported = None
		self.SSLV23 = None
		self.SSLV2 = None
		self.SSLV3 = None
		self.TLSV1 = None
		self.TLSV1_1 = None
		self.TLSV1_2 = None
		self.TLSV1_3 = None
		
		self.SSLV23_ciphers  = []
		self.SSLV2_ciphers   = []
		self.SSLV3_ciphers   = []
		self.TLSV1_ciphers   = []
		self.TLSV1_1_ciphers = []
		self.TLSV1_2_ciphers = []
		self.TLSV1_3_ciphers = []

		self.accepted_ciphers = {}
		self.rejected_ciphers = {}
		self.errored_ciphers = {}

	def from_db(session, scanid):
		scanid = int(scanid)
		results = []
		active_targets = session.query(TargetConnectivityInfo.target_id).filter(TargetConnectivityInfo.scan_id == scanid).filter(TargetConnectivityInfo.is_connectivity_ok == True)
		query = session.query(Target, CompressionScanResult.compression_name, FallbackScsvScanResult.supports_fallback_scsv, HeartbleedScanResult.is_vulnerable_to_heartbleed\
								, OpenSslCcsInjectionScanResult.is_vulnerable_to_ccs_injection, SessionRenegotiationScanResult.accepts_client_renegotiation\
								, SessionRenegotiationScanResult.supports_secure_renegotiation, RobotScanResult.robot_result_enum, EarlyDataScanResult.is_early_data_supported)\
									.filter(Target.id.in_(active_targets))\
									.join(CompressionScanResult, and_(CompressionScanResult.target_id == Target.id, CompressionScanResult.scan_id == scanid), isouter=True)\
									.join(FallbackScsvScanResult, and_(FallbackScsvScanResult.target_id == Target.id, FallbackScsvScanResult.scan_id == scanid), isouter=True)\
									.join(HeartbleedScanResult, and_(HeartbleedScanResult.target_id == Target.id, HeartbleedScanResult.scan_id == scanid), isouter=True)\
									.join(OpenSslCcsInjectionScanResult, and_(OpenSslCcsInjectionScanResult.target_id == Target.id, OpenSslCcsInjectionScanResult.scan_id == scanid), isouter=True)\
									.join(SessionRenegotiationScanResult, and_(SessionRenegotiationScanResult.target_id == Target.id, SessionRenegotiationScanResult.scan_id == scanid), isouter=True)\
									.join(RobotScanResult, and_(RobotScanResult.target_id == Target.id, RobotScanResult.scan_id == scanid), isouter=True)\
									.join(EarlyDataScanResult, and_(EarlyDataScanResult.target_id == Target.id, EarlyDataScanResult.scan_id == scanid), isouter=True)

		logger.debug('Report queriing for target properties')
		for target, compression_name, supports_fallback_scsv, is_vulnerable_to_heartbleed, is_vulnerable_to_ccs_injection, accepts_client_renegotiation, supports_secure_renegotiation,\
					robot_result_enum, is_early_data_supported in query.all():
			
			fr = FullResult()
			fr.target = target
			fr.compression_supported = compression_name
			fr.supports_fallback_scsv = supports_fallback_scsv
			fr.is_vulnerable_to_heartbleed = is_vulnerable_to_heartbleed
			fr.is_vulnerable_to_ccs_injection = is_vulnerable_to_ccs_injection
			fr.accepts_client_renegotiation = accepts_client_renegotiation
			fr.supports_secure_renegotiation = supports_secure_renegotiation
			fr.robot_result = robot_result_enum.name if robot_result_enum else 'N/A'
			fr.is_early_data_supported = is_early_data_supported

			
			logger.debug('Report queriing for target supported ciphers')
			cipersuiteres = session.query(CipherSuiteScanResult.id).filter(CipherSuiteScanResult.target_id == target.id).filter(CipherSuiteScanResult.scan_id == scanid)
			for ac in session.query(AcceptedCipherSuite.ssl_version, AcceptedCipherSuite.name).filter(AcceptedCipherSuite.ciphersuiterestuls_id.in_(cipersuiteres)).all():
				fr.accepted_ciphers[ac[0]] = 1
				if ac[0] == OpenSslVersionEnum.SSLV23:
					fr.SSLV23_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.SSLV2:
					fr.SSLV2_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.SSLV3:
					fr.SSLV3_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.TLSV1:
					fr.TLSV1_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.TLSV1_1:
					fr.TLSV1_1_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.TLSV1_2:
					fr.TLSV1_2_ciphers.append(ac[1])
				elif ac[0] == OpenSslVersionEnum.TLSV1_3:
					fr.TLSV1_3_ciphers.append(ac[1])
				
			logger.debug('Report queriing for target rejected ciphers')
			for rc in session.query(RejectedCipherSuite.ssl_version, RejectedCipherSuite.name).filter(RejectedCipherSuite.ciphersuiterestuls_id.in_(cipersuiteres)).group_by(RejectedCipherSuite.ssl_version).all():
				fr.rejected_ciphers[rc[0]] = 1

			logger.debug('Report queriing for target errored ciphers')
			for ec in session.query(RejectedCipherSuite.ssl_version, RejectedCipherSuite.name).filter(RejectedCipherSuite.ciphersuiterestuls_id.in_(cipersuiteres)).group_by(RejectedCipherSuite.ssl_version).all():
				fr.errored_ciphers[ec[0]] = 1

			fr.get_cipher_status()
			results.append(fr)

		return results

	def get_cipher_status(self):
		self.SSLV23 =  self.cipher_stat_map(OpenSslVersionEnum.SSLV23)
		self.SSLV2 =   self.cipher_stat_map(OpenSslVersionEnum.SSLV2)
		self.SSLV3 =   self.cipher_stat_map(OpenSslVersionEnum.SSLV3)
		self.TLSV1 =   self.cipher_stat_map(OpenSslVersionEnum.TLSV1)
		self.TLSV1_1 = self.cipher_stat_map(OpenSslVersionEnum.TLSV1_1)
		self.TLSV1_2 = self.cipher_stat_map(OpenSslVersionEnum.TLSV1_2)
		self.TLSV1_3 = self.cipher_stat_map(OpenSslVersionEnum.TLSV1_3)

	def cipher_stat_map(self, sslversion):
		if sslversion in self.accepted_ciphers:
			return 'SUPPORTED'
		elif sslversion in self.rejected_ciphers:
			return 'REJECTED'
		elif sslversion in self.errored_ciphers:
			return 'ERRORED'
		else:
			return 'DISABLED'


	def to_dict(self):
		t = OrderedDict()
		t['target'] = self.target.get_full_addr_s()
		t['compression_supported'] = a(self.compression_supported)
		t['supports_fallback_scsv'] = a(self.supports_fallback_scsv)
		t['is_vulnerable_to_heartbleed'] = a(self.is_vulnerable_to_heartbleed)
		t['is_vulnerable_to_ccs_injection'] = a(self.is_vulnerable_to_ccs_injection)
		t['accepts_client_renegotiation'] = a(self.accepts_client_renegotiation)
		t['supports_secure_renegotiation'] = a(self.supports_secure_renegotiation)
		t['robot_result'] = a(self.robot_result)
		t['is_early_data_supported'] = a(self.is_early_data_supported)
		t['SSLV23'] = a(self.SSLV23)
		t['SSLV2'] = a(self.SSLV2)
		t['SSLV3'] = a(self.SSLV3)
		t['TLSV1'] = a(self.TLSV1)
		t['TLSV1_1'] = a(self.TLSV1_1)
		t['TLSV1_2'] = a(self.TLSV1_2)
		t['TLSV1_3'] = a(self.TLSV1_3)
		
		t['SSLV23_accepted_ciphers'] = b(self.SSLV23_ciphers)
		t['SSLV2_accepted_ciphers'] = b(self.SSLV2_ciphers)
		t['SSLV3_accepted_ciphers'] = b(self.SSLV3_ciphers)
		t['TLSV1_accepted_ciphers'] = b(self.TLSV1_ciphers)
		t['TLSV1_1_accepted_ciphers'] = b(self.TLSV1_1_ciphers)
		t['TLSV1_2_accepted_ciphers'] = b(self.TLSV1_2_ciphers)
		t['TLSV1_3_accepted_ciphers'] = b(self.TLSV1_3_ciphers)		
		
		return t

	def get_hdr(full = False):
		return FullResult.HEADER if full == False else FullResult.HEADER_FULL

	def get_row(self, attrs):
		t = self.to_dict()
		return [str(t[x]) for x in attrs]

	def to_tsv(self, separator = '\t'):
		return separator.join(self.get_row(FullResult.get_hdr()))

def generate_report(session, scanid, full_report = False):
	logger.debug('generate_report')
	results = FullResult.from_db(session, scanid)
	data = []
	data.append(FullResult.get_hdr(full_report))
	for res in results:
		data.append(res.get_row(FullResult.get_hdr(full_report)))
		
	return data
