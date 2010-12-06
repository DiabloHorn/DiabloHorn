-- postdissector to make dnscat traffic more human readable
-- DiabloHorn http://diablohorn.wordpress.com
-- Thanks to #wireshark on freenode for the quick and excellent response, 
-- which resulted into the patch for the dns dissector that made access to dns.resp.primaryname possible
-- http://www.skullsecurity.org/wiki/index.php/Dnscat#Structure

-- required libs
local bit = require("bit")

-- info
print("dnscat postdissector loaded")

-- we need these fields from the dns packets
dc_dns_name = Field.new("dns.qry.name")
--this will only work if you have the developer version which includes a patch
dc_dns_rname = Field.new("dns.resp.primaryname")
dc_udp_dport = Field.new("udp.dstport")
dc_udp_sport = Field.new("udp.srcport")

-- declare our postdissector
dc_pd = Proto("dnscat","dnscat postdissector")

-- our fields
dc_tunneldata = ProtoField.string("dc_pd.tunneldata","Encoded Tunnel Data")
dc_td_sig = ProtoField.string("dc_pd.td_sig","Signature")
dc_td_flags = ProtoField.string("dc_pd.td_flags","Flags")
dc_td_ident = ProtoField.string("dc_pd.td_ident","Identifier")
dc_td_sess = ProtoField.string("dc_pd.td_session","Session")
dc_td_seqnum = ProtoField.string("dc_pd.td_seqnum","SeqNum")
dc_td_count = ProtoField.string("dc_pd.td_count","Count")
dc_td_err = ProtoField.string("dc_pd.td_error","Error")
dc_td_data = ProtoField.string("dc_pd.td_data","Data")
dc_td_gar = ProtoField.string("dc_pd.td_garbage","Garbage")
dc_td_dom = ProtoField.string("dc_pd.td_domain","Domain")
-- add our fields
dc_pd.fields = {dc_tunneldata,dc_td_sig,dc_td_flags,dc_td_ident,dc_td_sess,dc_td_seqnum,dc_td_count,dc_td_err,dc_td_data,dc_td_gar,dc_td_dom}

-- dissect each packet
function dc_pd.dissector(buffer,pinfo,tree)
    local udpsport = dc_udp_sport()
    local udpdport = dc_udp_dport()
    local dnsqryname = dc_dns_name()
    --this will only work if you have the developer version which includes a patch
    local dnsresname = dc_dns_rname()
    local subtree
    local parsed = {}
    
    subtree = tree:add(dc_pd,"dnscat data")
    if tostring(udpdport) == "53" then
        subtree:add(dc_tunneldata,tostring(dnsqryname))
        parsed = parseDC(tostring(dnsqryname))
    end
    
    --this will only work if you have the developer version which includes a patch
    if tostring(udpsport) == "53" then
        subtree:add(dc_tunneldata,tostring(dnsresname))
        parsed = parseDC(tostring(dnsresname))
    end
       
    subtree:add(dc_td_sig,tostring(parsed.signature))
    subtree:add(dc_td_flags,tostring(parsed.flags))
    subtree:add(dc_td_ident,tostring(parsed.identifier))
    subtree:add(dc_td_sess,tostring(parsed.session))
    subtree:add(dc_td_seqnum,tostring(parsed.seqnum))
    subtree:add(dc_td_count,tostring(parsed.count))
    subtree:add(dc_td_err,tostring(parsed.err))
    subtree:add(dc_td_data,tostring(parsed.asciidata))
    subtree:add(dc_td_gar,tostring(parsed.garbage))
    subtree:add(dc_td_dom,tostring(parsed.domain))        
end -- end dissector function

-- main dissecting logic

-- split the request into an array of subdomain
function getsubs(data)
    -- empty table to hold the subs
    local subs = {}
    for sub in data:gmatch("[^%.]+") do
        table.insert(subs,sub)
    end
    return subs
end

-- decode the flags to human readable strings
function decodeflags(data)
    -- protocol flags
    local FLAG_STREAM = 0x00000001
-- deprecated
    local FLAG_SYN = 0x00000002
    local FLAG_ACK = 0x00000004 
-- end of deprecated
    local FLAG_RST = 0x00000008
    local FLAG_HEX = 0x00000010
    local FLAG_SESSION = 0x00000020
    local FLAG_IDENTIFIER = 0x00000040

    -- convert string to number
    local hFlags = tonumber(data,16)
    --setup the flags table
    local Flags = {} -- st=nil,sy=nil,ac=nil,rs=nil,he=nil,se=nil,id=nil
    -- let's see which are set
    if bit.band(hFlags,FLAG_STREAM) ~= 0 then
        table.insert(Flags,"stream")
    end
-- deprecated
    if bit.band(hFlags,FLAG_SYN) ~= 0 then
        table.insert(Flags,"syn")
    end        
    if bit.band(hFlags,FLAG_ACK) ~= 0 then
        table.insert(Flags,"ack")
    end        
-- end of deprecated
    if bit.band(hFlags,FLAG_RST) ~= 0 then
        table.insert(Flags,"rst")
    end        
    if bit.band(hFlags,FLAG_HEX) ~= 0 then
        table.insert(Flags,"hex")
    end        
    if bit.band(hFlags,FLAG_SESSION) ~= 0 then
        table.insert(Flags,"session")
    end        
    if bit.band(hFlags,FLAG_IDENTIFIER) ~= 0 then
        table.insert(Flags,"identifier")                                
    end
    return Flags
end

-- decode the error code to something human readable
-- overcomplicated...but hey I wanted to use the bitopt lib again
function decoderr(data)
    local ERR_SUCCESS = 0x00000000
    local ERR_BUSY = 0x00000001
    local ERR_INVSTATE = 0x00000002
    local ERR_FIN = 0x00000003
    local ERR_BADSEQ = 0x00000004
    local ERR_NOTIMPLEMENTED = 0x00000005
    local ERR_TEST = 0xFFFFFFFF
    local err = {}
    local herr = tonumber(data,16)

    if bit.tobit(ERR_SUCCESS) == bit.tobit(herr) then
        table.insert(err,"success")
    end
    
    if bit.tobit(ERR_BUSY) == bit.tobit(herr) then
        table.insert(err,"busy")
    end
    
    if bit.tobit(ERR_INVSTATE) == bit.tobit(herr) then
        table.insert(err,"invalidstate")
    end
    
    if bit.tobit(ERR_FIN) == bit.tobit(herr) then
        table.insert(err,"confin")
    end
    
    if bit.tobit(ERR_BADSEQ) == bit.tobit(herr) then
        table.insert(err,"badseqnum")
    end
    
    if bit.tobit(ERR_NOTIMPLEMENTED) == bit.tobit(herr) then
        table.insert(err,"notimplemented")
    end
    
    if bit.tobit(ERR_TEST) == bit.tobit(herr) then
        table.insert(err,"contest")
    end   
    return err                     
end

-- decode netbios data to ascii
function decodenetbios(data)
    local ldata = data:upper()
    local dec = ""
    for sub in ldata:gmatch("%u%u") do
        -- perform operation in decimal and convert final value from hex XX to decimal   
        --local decnum = tonumber(((sub:byte(1)-65) .. (sub:byte(2)-65)),16)
        -- Thanks to Animal for making me realize the concat has to be with hexnumbers
        local decnum = tonumber((bit.tohex(sub:byte(1)-65,1) .. bit.tohex(sub:byte(2)-65,1)),16)  
        --print(decnum,sub)
        if decnum > 31 and decnum < 127 then
            dec = dec .. string.char(decnum)
        else
            dec = dec .. "."
        end
        decnum = 0
        sub = ""
    end
    return dec
end

-- decode hex data to ascii
function decodehex(data)
    local dec = ""
    for sub in data:gmatch("%x%x") do
        local decnum = tonumber(sub,16)
        if decnum > 31 and decnum < 127 then
            dec = dec .. string.char(decnum)
        else
            dec = dec .. "."
        end
    end
    return dec
end

-- main flow implementation
-- lacks implementation of syn/ack since it's deprecated
function parseDC(data)
    local finalparsed = {}
    local x = getsubs(data)

    finalparsed["signature"] = x[1]
    table.remove(x,1)
    finalparsed["flags"] = table.concat(decodeflags(x[1]),",")
    table.remove(x,1)

    if finalparsed["flags"]:find("identifier") ~= nil then
        finalparsed["identifier"] = x[1]
        table.remove(x,1)
        if finalparsed["flags"]:find("session") ~= nil then
            finalparsed["session"] = x[1]
            table.remove(x,1)
        end
    elseif finalparsed["flags"]:find("session") ~= nil then
        finalparsed["session"] = x[1]
        table.remove(x,1)
    end

    if finalparsed["flags"]:find("stream") ~= nil then
        finalparsed["seqnum"] = x[1]
        table.remove(x,1)
    end
    
    if finalparsed["flags"]:find("rst") ~= nil then 
        finalparsed["err"] = table.concat(decoderr(x[1]),",")
        table.remove(x,1)
        finalparsed["garbage"] = x[1]
        finalparsed["domain"] = x[2]
    else
        finalparsed["count"] = x[1]
        table.remove(x,1)
        -- if you wonder the character # == len()
        finalparsed["garbage"] = x[#x-1]
        finalparsed["domain"] = x[#x]
        table.remove(x,(#x))
        table.remove(x,(#x))
        -- so we either got data or we don't
        finalparsed["asciidata"] = ""
        while #x > 0 do
            if finalparsed["flags"]:find("hex") == nil then
                finalparsed["asciidata"] = finalparsed["asciidata"] .. decodenetbios(x[1])
            else
                finalparsed["asciidata"] = finalparsed["asciidata"] .. decodehex(x[1])
            end
            table.remove(x,1)
        end
    end -- end of rst check
    
    return finalparsed
end -- end of parseDC function

-- end of main dissecting logic

-- register ourselfs
register_postdissector(dc_pd)
