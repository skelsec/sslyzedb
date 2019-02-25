import enum

from sslyze.ssl_settings import TlsWrappedProtocolEnum
from nassl.ssl_client import OpenSslVersionEnum
from sslyze.plugins.robot_plugin import RobotScanResultEnum
from sslyze.plugins.certificate_info_plugin import OcspResponseStatusEnum 

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Table, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker

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

from datetime import datetime, timedelta, timezone
import ipaddress
from .. import logger

Basemodel = declarative_base()

def create_db(connection, verbosity = 0):
	logger.info('Creating database %s' % connection)
	engine = create_engine(connection, echo=True if verbosity > 1 else False) #'sqlite:///dump.db'	
	Basemodel.metadata.create_all(engine)
	logger.info('Done creating database %s' % connection)

def get_session(connection, verbosity = 0):
	logger.debug('Connecting to DB')
	engine = create_engine(connection, echo=True if verbosity > 1 else False) #'sqlite:///dump.db'	
	logger.debug('Creating session')
	# create a configured "Session" class
	Session = sessionmaker(bind=engine)
	# create a Session
	return Session()

class SSLYZECommand(enum.Enum):
	ALL = -1
	CERTIFICATEINFO = 0
	SSLV20 = 1
	SSLV30 = 2
	TLSV10 = 3
	TLSV11 = 4
	TLSV12 = 5
	TLSV13 = 6
	COMPRESSION = 7
	FALLBACKSCSV = 8
	HEARTBLEED = 9
	OPENSSLCCSINJECTION = 10
	SESSIONRENEGOTIATION = 11
	SESSIONRESUMPTIONSUPPORT = 12
	ROBOT = 13
	EARLYDATA = 14

command_map = {
	SSLYZECommand.ALL : [
		CertificateInfoScanCommand,
		Sslv20ScanCommand,
		Sslv30ScanCommand,
		Tlsv10ScanCommand,
		Tlsv11ScanCommand, 
		Tlsv12ScanCommand,
		Tlsv13ScanCommand,
		CompressionScanCommand,
		FallbackScsvScanCommand,
		HeartbleedScanCommand,
		OpenSslCcsInjectionScanCommand,
		SessionRenegotiationScanCommand,
		SessionResumptionSupportScanCommand,
		RobotScanCommand,
		EarlyDataScanCommand,
	],
	SSLYZECommand.CERTIFICATEINFO : [CertificateInfoScanCommand],
	SSLYZECommand.SSLV20 : [Sslv20ScanCommand],
	SSLYZECommand.SSLV30 : [Sslv30ScanCommand],
	SSLYZECommand.TLSV10 : [Tlsv10ScanCommand],
	SSLYZECommand.TLSV11 : [Tlsv11ScanCommand],
	SSLYZECommand.TLSV12 : [Tlsv12ScanCommand],
	SSLYZECommand.TLSV13 : [Tlsv13ScanCommand],
	SSLYZECommand.COMPRESSION : [CompressionScanCommand],
	SSLYZECommand.FALLBACKSCSV : [FallbackScsvScanCommand],
	SSLYZECommand.HEARTBLEED : [HeartbleedScanCommand],
	SSLYZECommand.OPENSSLCCSINJECTION : [OpenSslCcsInjectionScanCommand],
	SSLYZECommand.SESSIONRENEGOTIATION : [SessionRenegotiationScanCommand],
	SSLYZECommand.SESSIONRESUMPTIONSUPPORT : [SessionResumptionSupportScanCommand],
	SSLYZECommand.ROBOT : [RobotScanCommand],
	SSLYZECommand.EARLYDATA : [EarlyDataScanCommand],
}

command_map_rev = {
	CertificateInfoScanCommand : SSLYZECommand.CERTIFICATEINFO,
	Sslv20ScanCommand : SSLYZECommand.SSLV20,
	Sslv30ScanCommand : SSLYZECommand.SSLV30,
	Tlsv10ScanCommand : SSLYZECommand.TLSV10,
	Tlsv11ScanCommand : SSLYZECommand.TLSV11,
	Tlsv12ScanCommand : SSLYZECommand.TLSV12,
	Tlsv13ScanCommand : SSLYZECommand.TLSV13,
	CompressionScanCommand : SSLYZECommand.COMPRESSION,
	FallbackScsvScanCommand : SSLYZECommand.FALLBACKSCSV,
	HeartbleedScanCommand : SSLYZECommand.HEARTBLEED,
	OpenSslCcsInjectionScanCommand : SSLYZECommand.OPENSSLCCSINJECTION,
	SessionRenegotiationScanCommand : SSLYZECommand.SESSIONRENEGOTIATION,
	SessionResumptionSupportScanCommand : SSLYZECommand.SESSIONRESUMPTIONSUPPORT,
	RobotScanCommand : SSLYZECommand.ROBOT,
	EarlyDataScanCommand : SSLYZECommand.EARLYDATA,
}

scan_targets_table = Table('scan_targets_table', Basemodel.metadata,
    Column('scan_id', Integer, ForeignKey('scans.id')),
    Column('target_id', Integer, ForeignKey('targets.id'))
)

class Project(Basemodel):
	__tablename__ = 'projects'

	id = Column(Integer, primary_key=True)
	name = Column(String)
	created_at = Column(DateTime, default=datetime.utcnow)
	cmd = Column(String)

	def __init__(self, name, cmd):
		self.name = name
		self.cmd = cmd

class Target(Basemodel):
	__tablename__ = 'targets'

	id = Column(Integer, primary_key=True)
	scans = relationship("Scan", secondary=scan_targets_table,back_populates="targets", lazy='dynamic')
	added_at = Column(DateTime, default=datetime.utcnow)
	ip_address = Column(String)
	domain_name = Column(String)
	port = Column(Integer)
	protocol = Column(Enum(TlsWrappedProtocolEnum))

	def get_addr(self):
		return self.domain_name if self.domain_name is not None else self.ip_address

	def get_full_addr_s(self):
		return ':'.join([self.get_addr(), str(self.port)])

	@staticmethod
	def from_line(line):
		temp = line.split(':')
		if len(temp) == 1:
			address = temp[0]
			port = 443
		else:
			address = temp[0]
			port = int(temp[1])

		try:
			ipaddress.ip_address(address)
			target = Target(ip_address = address, port = port)
		except Exception as e:
			logger.debug('Target parsing - its normal to get errors here Exc: %s' % e)
			target = Target(domain_name = address, port = port)
			pass		
		
		return target

	def __init__(self, ip_address = None, domain_name = None, port = None, protocol = TlsWrappedProtocolEnum.PLAIN_TLS):
		self.ip_address = ip_address
		self.port = port
		self.domain_name = domain_name
		self.protocol = protocol

class TargetConnectivityInfo(Basemodel):
	__tablename__ = 'targetconnectivityinfos'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	is_connectivity_ok = Column(Boolean)
	

class Scan(Basemodel):
	__tablename__ = 'scans'

	id = Column(Integer, primary_key=True)
	project_id = Column(Integer, ForeignKey('projects.id'))
	started_at = Column(DateTime, default=datetime.utcnow)
	network_retries = Column(Integer, default = 3)
	network_timeout = Column(Integer, default = 5)
	max_processes_nb = Column(Integer, default = 12)
	max_processes_per_hostname_nb = Column(Integer, default = 3)


	targets = relationship("Target", secondary=scan_targets_table,back_populates="scans", lazy='dynamic')
	scan_commands = relationship("ScanCommand", back_populates="scan")

class ScanCommand(Basemodel):
	__tablename__ = 'scancommands'
	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	command = Column(Enum(SSLYZECommand))
	scan = relationship("Scan", back_populates="scan_commands")
	


####################################################################################
class CertificateInfoScanResult(Basemodel):
	__tablename__ = 'certificateinfoscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))
	successful_trust_store_id = Column(Integer, ForeignKey('truststores.id'))

	certificate_chain = relationship("Certificate")
	path_validation_result_list = relationship("PathValidationResult")
	path_validation_error_list = relationship("PathValidationError")
	successful_trust_store = relationship("TrustStore", foreign_keys=[successful_trust_store_id])
	verified_certificate_chain = relationship("Certificate")
	certificate_matches_hostname = Column(Boolean)
	is_leaf_certificate_ev = Column(Boolean)
	certificate_has_must_staple_extension = Column(Boolean)
	certificate_included_scts_count = Column(Integer)
	#ocsp_response = Column(Boolean)
	ocsp_response_status = Column(Enum(OcspResponseStatusEnum))
	is_ocsp_response_trusted = Column(Boolean)
	has_sha1_in_certificate_chain = Column(Boolean)
	has_anchor_in_certificate_chain = Column(Boolean)
		

class Certificate(Basemodel):
	__tablename__ = 'certificates'

	id = Column(Integer, primary_key=True)
	certificateinfoscanresult_id = Column(Integer, ForeignKey('certificateinfoscanresults.id'))
	index = Column(Integer)
	certificate_data = Column(String)

	@staticmethod
	def from_result(res_id, idx, result):
		res = Certificate()
		res.certificateinfoscanresult_id = res_id
		res.index = idx
		res.certificate_data = result
		return res

class PathValidationResult(Basemodel):
	__tablename__ = 'pathvalidationresults'

	id = Column(Integer, primary_key=True)
	certificateinfoscanresult_id = Column(Integer, ForeignKey('certificateinfoscanresults.id'))

	trust_store_id = Column(Integer, ForeignKey('truststores.id'))
	trust_store = relationship("TrustStore")
	verify_string = Column(String)
	is_certificate_trusted = Column(Boolean)

class PathValidationError(Basemodel):
	__tablename__ = 'pathvalidationerrorresults'

	id = Column(Integer, primary_key=True)
	trust_store_id = Column(Integer, ForeignKey('truststores.id'))
	certificateinfoscanresult_id = Column(Integer, ForeignKey('certificateinfoscanresults.id'))

	trust_store = relationship("TrustStore")
	error_message = Column(String)

class TrustStore(Basemodel):
	__tablename__ = 'truststores'

	id = Column(Integer, primary_key=True)
	certificateinfoscanresult_id = Column(Integer, ForeignKey('certificateinfoscanresults.id'))

	path = Column(String)
	name = Column(String)
	version = Column(String)

	@staticmethod
	def from_result(res_id, result):
		res = TrustStore()
		res.certificateinfoscanresult_id = res_id
		res.path = result.path
		res.name = result.name
		res.version = result.version
		return res



####################################################################################

class CipherSuiteScanResult(Basemodel):
	__tablename__ = 'ciphersuiterestuls'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	accepted_cipher_list = relationship("AcceptedCipherSuite", back_populates="ciphersuitescanresult")
	rejected_cipher_list = relationship("RejectedCipherSuite")
	errored_cipher_list = relationship("ErroredCipherSuite")
	preferred_cipher_id = Column(Integer, ForeignKey('scans.id'))

	@staticmethod
	def from_result(session, project_id, scan_id, target_id, result):
		pass

class AcceptedCipherSuite(Basemodel):
	__tablename__ = 'acceptedciphers'

	id = Column(Integer, primary_key=True)
	ciphersuiterestuls_id = Column(Integer, ForeignKey('ciphersuiterestuls.id'))
	ciphersuitescanresult = relationship("CipherSuiteScanResult", back_populates="accepted_cipher_list")

	name = Column(String)
	openssl_name = Column(String)
	ssl_version = Column(Enum(OpenSslVersionEnum))
	is_anonymous = Column(Boolean)
	key_size = Column(Integer)
	post_handshake_response = Column(String)

	@staticmethod
	def from_result(result):
		ac = AcceptedCipherSuite()
		ac.name = result.name
		ac.openssl_name = result.openssl_name
		ac.ssl_version = result.ssl_version
		ac.is_anonymous = result.is_anonymous
		ac.key_size = result.key_size
		ac.post_handshake_response = result.post_handshake_response
		return ac

class RejectedCipherSuite(Basemodel):
	__tablename__ = 'rejectedciphers'

	id = Column(Integer, primary_key=True)
	ciphersuiterestuls_id = Column(Integer, ForeignKey('ciphersuiterestuls.id'))

	name = Column(String)
	openssl_name = Column(String)
	ssl_version = Column(Integer)
	is_anonymous = Column(Boolean)
	handshake_error_message = Column(String)

	@staticmethod
	def from_result(result):
		rc = RejectedCipherSuite()
		rc.name = result.name
		rc.openssl_name = result.openssl_name
		rc.ssl_version = result.ssl_version
		rc.is_anonymous = result.is_anonymous
		rc.handshake_error_message = result.handshake_error_message
		return rc

class ErroredCipherSuite(Basemodel):
	__tablename__ = 'erroredciphers'

	id = Column(Integer, primary_key=True)
	ciphersuiterestuls_id = Column(Integer, ForeignKey('ciphersuiterestuls.id'))

	name = Column(String)
	openssl_name = Column(String)
	ssl_version = Column(Integer)
	is_anonymous = Column(Boolean)
	error_message = Column(String)

	@staticmethod
	def from_result(result):
		ec = ErroredCipherSuite()
		ec.name = result.name
		ec.openssl_name = result.openssl_name
		ec.ssl_version = result.ssl_version
		ec.is_anonymous = result.is_anonymous
		ec.error_message = result.error_message
		return ec

####################################################################################

class SessionResumptionSupportScanResult(Basemodel):
	__tablename__ = 'sessionresumptionscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	attempted_resumptions_nb = Column(Integer)
	successful_resumptions_nb = Column(Integer)
	failed_resumptions_nb = Column(Integer)
	errored_resumptions_list = relationship("SessionResumptionErrors")
	is_ticket_resumption_supported = Column(Boolean)
	ticket_resumption_failed_reason = Column(String)
	ticket_resumption_exception = Column(String)

class SessionResumptionErrors(Basemodel):
	__tablename__ = 'sessionresumptionerrors'

	id = Column(Integer, primary_key=True)
	resumption_id = Column(Integer, ForeignKey('sessionresumptionscanresults.id'))

	error = Column(String)

class CompressionScanResult(Basemodel):
	__tablename__ = 'compressionscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	compression_name = Column(String)
	

class FallbackScsvScanResult(Basemodel):
	__tablename__ = 'fallbackscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	supports_fallback_scsv = Column(Boolean)

class HeartbleedScanResult(Basemodel):
	__tablename__ = 'heartbleedscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	is_vulnerable_to_heartbleed = Column(Boolean)

class OpenSslCcsInjectionScanResult(Basemodel):
	__tablename__ = 'ccsinjectionscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	is_vulnerable_to_ccs_injection = Column(Boolean)

class SessionRenegotiationScanResult(Basemodel):
	__tablename__ = 'sessionrenegotiationscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	accepts_client_renegotiation = Column(Boolean)
	supports_secure_renegotiation = Column(Boolean)

class RobotScanResult(Basemodel):
	__tablename__ = 'robotscanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	robot_result_enum = Column(Enum(RobotScanResultEnum))

class EarlyDataScanResult(Basemodel):
	__tablename__ = 'earlydatascanresults'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	is_early_data_supported = Column(Boolean)

class FailedCommands(Basemodel):
	__tablename__ = 'failedcommands'

	id = Column(Integer, primary_key=True)
	scan_id = Column(Integer, ForeignKey('scans.id'))
	target_id = Column(Integer, ForeignKey('targets.id'))

	failed_command = Column(Enum(SSLYZECommand))
	error_message = Column(String)