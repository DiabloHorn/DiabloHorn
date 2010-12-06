##
# mod_negotiation bruter
# http://httpd.apache.org/docs/1.3/content-negotiation.html
##

require 'rex/proto/http'
require 'msf/core'
require 'thread'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'   		=> 'HTTP Mod Negotiation Bruter',
			'Description'	=> %q{
				This module performs a brute force attack using mod_negotiation on the given host(s). Returns the ip and the found file if the host is vulnerable.
			},
			'Author' 		=> [ 'diablohorn [at] gmail.com' ],
			'License'		=> BSD_LICENSE,
			'Version'		=> '0.1'))

		register_options(
			[
				OptString.new('PATH', [ true,  "The path to detect mod_negotiation", '/']),
				OptString.new('FILEPATH',[true, "path to file with file names",'/opt/metasploit3/msf3/data/wmap/wmap_files.txt'])
			], self.class)

		register_advanced_options(
			[
				OptBool.new('NoDetailMessages', [ false, "Do not display detailed test messages", true ]),
				OptInt.new('TestThreads', [ true, "Number of test threads", 25])
			], self.class)
	end

	def run_host(ip)
		conn = true
		ecode = nil
		emesg = nil

		tpath = datastore['PATH']
		tfile = datastore['FILEPATH']
		
		if tpath[-1,1] != '/'
			tpath += '/'
		end
		
		#load the file with filenames into memory
		queue = []
		File.open(datastore['FILEPATH'], 'r').each_line do |fn|
			queue << fn.strip
		end

		vhost = datastore['VHOST'] || ip
		prot  = datastore['SSL'] ? 'https' : 'http'

        #
        # Send the request and parse the response headers for an alternates header
        #
		begin
		    queue.each do |dirname|
			reqpath = tpath+dirname
		        #send the request the accept header is key here
			    res = send_request_cgi({
				    'uri'  		=>  reqpath,
				    'method'   	=> 'GET',
				    'ctype'     => 'text/html',
				    'headers'	=> {'Accept' => 'a/b'}
			    }, 20)

			    return if not res
                #check for alternates header and parse them
                if(res.code == 406)
                    chunks = res.headers.to_s.scan(/"(.*?)"/i).flatten
                    chunks.each do |chunk|
                        chunk = chunk.to_s
                        print_status("#{ip} #{tpath}#{chunk}")
                    end
                end
            end            
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

		return if not conn
	end
end

