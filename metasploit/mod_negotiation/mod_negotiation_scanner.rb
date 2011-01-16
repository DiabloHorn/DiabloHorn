##
# $Id: $
##

require 'rex/proto/http'
require 'msf/core'
require 'thread'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'Apache HTTPD mod_negotiation scanner',
			'Description'	=> %q{
				This module scans the webserver of the given host(s) for the existence of mod_negotiate. Displays the ip address if the webserver has mod_negotiation enabled.
			},
			'Author' 		=> [ 'diablohorn [at] gmail.com' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision: $'))

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to detect mod_negotiation", '/']),
				OptString.new('FILENAME',[true, "Filename to use as a test",'index'])
			], self.class)
	end

	def run_host(ip)
		conn = true
		ecode = nil
		emesg = nil

		tpath = datastore['PATH']
		tfile = datastore['FILENAME']
		
		if tpath[-1,1] != '/'
			tpath += '/'
		end

		vhost = datastore['VHOST'] || ip
		prot  = datastore['SSL'] ? 'https' : 'http'

		#
		# Send the request and parse the response headers for an alternates header
		#
		begin
			#send the request the accept header is key here
			res = send_request_cgi({
				'uri'  		=>  tpath+tfile,
				'method'   	=> 'GET',
				'ctype'     => 'text/html',
				'headers'	=> {'Accept' => 'a/b'}
			}, 20)

			return if not res
			#check for alternates header
			if(res.code == 406)
				print_status("#{ip}")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

		return if not conn
	end
end

