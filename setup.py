from setuptools import setup, find_packages

setup(
	# Application name:
	name="sslyzedb",

	# Version number (initial):
	version="0.0.1",

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/sslyzedb",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="DB driven SSLyze scanner",
	long_description="DB driven SSLyze scanner",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'sslyze',
		'sqlalchemy',
	],
	entry_points={
		'console_scripts': [
			'sslyzedb = sslyzedb.__main__:run',
		],
	}
)