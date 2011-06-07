#!/usr/bin/env ruby
#Use BING to search for websites hosted on a ip address and return the current ip they have
#Author: DiabloHorn (http://diablohorn.wordpress.com)
#does the same as the python version, was curious about ruby cli coding

#Working with the bing engine
#example url: http://api.bing.net/xml.aspx?AppId=<APPID>&Version=2.2&Query=ip:74.207.254.18&Sources=web&web.count=50&web.offset=0

#even though ruby doesn't really have a main, according to wikipedia
# http://en.wikipedia.org/wiki/Main_function#Ruby

require 'optparse'
require 'net/http'
require 'uri'
require 'cgi'
require 'rexml/document'
require 'socket'


class Bing
    BURL = "http://api.bing.net"
    BPATH = "/xml.aspx"
    
    def initialize(bingid,bingurl=BURL)
        @params = {"appid" => "#{bingid}","Version" => "2.2","Query" => "","Sources" => "Web","web.count" => "50","web.offset" => "0"}
        @uri = URI.parse(bingurl)
        @foundurls = {}
    end
    
    private
    def page_content()
        page_url = BPATH + "?" + @params.collect{|k,v| "#{k}=#{CGI::escape(v.to_s)}"}.join('&')
        req = Net::HTTP::Get.new(page_url)
        http = Net::HTTP.new(@uri.host, @uri.port)
        response = http.start do |http| http.request(req) end
        response.body
    end
    
    private 
    def content_parse(xml,ttr=false)
    #http://www.componentworkshop.com/blog/2009/07/13/using-the-bing-xml-search-api-with-ruby
        doc = REXML::Document.new(xml)
        if(ttr)
            doc.elements.each("SearchResponse/web:Web") do |t| @totalRes = t.get_elements("web:Total")[0].text end
        end
        doc.elements.each("SearchResponse/web:Web/web:Results/web:WebResult") do |result|
            ruri = URI.parse(result.get_elements("web:Url")[0].text)
            begin
                @foundurls[ruri.host.to_s] = Socket.getaddrinfo(ruri.host.to_s,"http","AF_INET")[0][3]
            rescue
                @foundurls[ruri.host.to_s] = nil
            end
        end
    end
    
    public
    def ip_query(ip)
        @foundurls.clear
        @params["Query"] = "ip:"+ip
        @params["web.offset"] = "0"
        puts "Searching: #{@params["Query"]}"
        xmldata = page_content()
        content_parse(xmldata,true)
        pages = (@totalRes.to_i / 50)
        puts "Results Found: " + @totalRes
        puts "Pages: " + pages.to_s
        for i in (0..pages)
            @params["web.offset"] = (i+1).to_s
            content_parse(page_content())
        end
        @foundurls
    end
end

if __FILE__ == $PROGRAM_NAME
    #parse command line arguments
    options = {}
    optparse = OptionParser.new do |opts|
        opts.banner = "[*] DiabloHorn http://diablohorn.wordpress.com\n" + 
                        "[*] Use BING to search for websites hosted on a ip address\n" + 
                        "[*] " + $PROGRAM_NAME + " -a <appid> -i ([file:location] | [ip])\n"
    
        #application specific options
                #switch has mandatory argument 
        opts.on("-a", "--bingappid BINGAPPID", "BING AppID") do |a|
            options[:bappid] = a
        end  
                #switch has mandatory argument (file:[location], inspired by metasploit)
        opts.on("-i", "--ipaddress IP", "IP address (use file:[location] to use a file") do |i|
            options[:ip] = i
        end

        opts.on_tail("-v", "--[no-]verbose", "Run verbosely") do |v|
            options[:verbose] = v
        end
        
        opts.on_tail("-h", "--help", "Show this message") do
            puts opts
            exit
        end    
    end
    
    #http://stackoverflow.com/questions/1541294/how-do-you-specify-a-required-switch-not-argument-with-ruby-optionparser
    begin
        optparse.parse!
        mandatory = [:bappid,:ip]
        missing = mandatory.select{ |param| options[param].nil? }
        if not missing.empty?
            puts "Missing options: #{missing.join(', ')}"
            puts optparse
            exit                                                                                                                                     
        end
    rescue OptionParser::InvalidOption, OptionParser::MissingArgument
        puts $!.to_s
        puts optparse       
        exit
    end
    
    #start processing
    #first let's check if it's a file or a single ip.
    bs = Bing.new(options[:bappid])
    
    if options[:ip][0,5] == "file:"
        #get file path and cycle through it
        File.open(options[:ip][5,options[:ip].length], "r") do |infile|
            while (line = infile.gets)
                urlsfound = bs.ip_query(line.rstrip) 
                urlsfound.each do|k,v|
                    puts "#{k}:#{v}"
                end
            end
        end
    else
        #quick and painless one lookup
        urlsfound = bs.ip_query(options[:ip]) 
        urlsfound.each do|k,v|
            puts "#{k}:#{v}"
        end
    end
end
