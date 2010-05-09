#! /usr/bin/ruby

#Ruby DenyHosts plugin to report attacker to ISP
#
#Copyright 2008 Nazar Aziz - nazar@panthersoftware.com

#######################################################################################
####### PLEASE READ INSTRUCTIONS: http://github.com/nazar/report-hack-isp/wikis #######
#######################################################################################

require 'net/smtp'

#SMTP server
SMTP_SERVER = 'localhost'
SMTP_PORT   = 25

#EMAIL message setup
EMAIL_FROM    = 'ADD_YOUR_RETURN_EMAIL_HERE' ####### ADD YOUR ACTUALL EMAIL ADDRESS HERE ##########
EMAIL_SUBJECT = 'Security Alert - Your Server May Have Been Hacked!'
# Leave empty to not send a mail to a CC address
CC = ''
# Same as for the CC address, you probably only need one of these
BCC = ''

#LOG_FILE = SSHD's log file ###### UPDATE THIS TO YOUR ACTUAL SSHD LOG FILE LOCATION #####
LOG_FILE = '/var/log/sshd/*'  

#misc
TIME_LOCALE = 'GMT+1'
EMAIL_LOG_FILE    = '/var/log/notify_isp.log'  ##### CHECK PERMISSIONS ON DESTINATION DIRECTORY. 

#guess apps... override if required
GREP_BIN  = `which grep`.strip
CAT_BIN   = `which cat`.strip
WHOIS_BIN = `which whois`.strip
HOST_BIN  = `which host`.strip
TOUCH_BIN = `which touch`.strip

#check that we have all our BINs
raise 'Could not find grep on your system. Manually configure GREP_BIN' if GREP_BIN == ''
raise 'Could not find cat on your system. Manually configure CAT_BIN' if CAT_BIN == ''
raise 'Could not find whois on your system. Manually configure WHOIS_BIN' if WHOIS_BIN == ''
raise 'Could not find host on your system. Manually configure HOST_BIN' if HOST_BIN == ''
raise 'Could not find touch on your system. Manually configure TOUCH_BIN' if HOST_BIN == ''


################# UTILS ########################
def time2str( tm )
  # [ruby-list:7928]
  gmt = Time.at(tm.to_i)
  gmt.gmtime
  offset = tm.to_i - Time.local(*gmt.to_a[0,6].reverse).to_i

  sprintf '%s, %s %s %d %02d:%02d:%02d %+.2d%.2d',
          tm.strftime('%a'), tm.mday, tm.strftime('%B'),
          tm.year, tm.hour, tm.min, tm.sec,
          *(offset / 60).divmod(60)
end

def get_email_message(to_address, offender, evidence)
  to_cc = CC.length > 0 ? "\nCC: #{CC}" : ''
  to_bcc = BCC.length > 0 ? "\nBCC: #{BCC}" : ''

  email_message = <<EOF
From: #{EMAIL_FROM}
To: #{to_address}#{to_cc}#{to_bcc}
Subject: #{EMAIL_SUBJECT}
Date: #{time2str(Time.now)}

To whom it may concern.

We have detected a hack attempt originating from your network from ip: #{offender}

This suggests that the above server has been compromised and is a participant in a botnet.

This means that this server has been hacked and now, in turn, is attempting to hack other servers on the Internet.

This IP address has now been blacklisted to protect our service from further brute force attacks. Furthermore, this IP address has been uploaded to DenyHosts' centralised database. This means that this IP address will also shortly be blacklisted by any member who queries DenyHosts' central database.

An excerpt from our logfiles. All times shown are in #{TIME_LOCALE}:

#{evidence}

Regards.
EOF

end

def get_contacts_for_host(lookup_host)
  result = []
  lookup = eval("`#{WHOIS_BIN} #{lookup_host} | #{GREP_BIN} @`") #return any line that contains an @ symbol
  lookup.each_line do |line|
    email = line[/([-a-z0-9]+[\w\.\-\+]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})/i]
    result << email unless email == nil
  end
  #if contacts includes an abuse@ address then only send it to those.
  tmp = result.select { |email| email[/abuse@/] }
  result = tmp if tmp.length > 0
  result.uniq! if result.length > 1
  return result.uniq
end


################# MAIN ##########################

#extract ip/domain from passed parameter
if ARGV.length > 0
  host = ARGV[0]
else
  raise 'No ip address or host given. Exiting'
end

#make sure the EMAIL_LOG_FILE exists
eval("`#{TOUCH_BIN} #{EMAIL_LOG_FILE}`")

#extract all email contacts for given host
contacts = get_contacts_for_host(host)

#lookup top level domain name and extract domain contact info
#if given ip then lookup to hostname
if host[/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/]
  host_domain = eval("`#{HOST_BIN} #{host}`").strip
  unless host_domain =~ /not found:/ 
    host_domain = host_domain[/.+\.(\w+\.\w+)/,1] 
  else #no good... no revers DNS pointer
    host_domain = nil
  end
else 
  host_domain = host[/.+\.(\w+\.\w+)/,1]
end

if host_domain
  domain_contacts = get_contacts_for_host(host_domain)
  contacts << domain_contacts if domain_contacts.length > 0
end

#filter out duplicates one last time
contacts.uniq! if contacts.length > 1

raise "No email addresses were returned" unless contacts.length > 0

#extract evidence from ssh log file using the reported host as a filter
evidence = eval("`#{CAT_BIN} #{LOG_FILE} | #{GREP_BIN} #{host}`").strip
raise "No evidence found for #{host}. Aborting" unless evidence && (evidence.length > 0)

#workaround for DenyHosts that runs the plugin evrytime an IP is added against all blacklisted IPS
sent = eval("`#{CAT_BIN} #{EMAIL_LOG_FILE} | #{GREP_BIN} #{host}`").strip
raise "Host #{host} has already been reported. Not reporting again." if sent && sent.length > 0

#are we CC/BCCing ourselves?
contacts << CC if CC.length > 0
contacts << BCC if BCC.length > 0

#by the time we get here we have evidence against a newly reported host
Net::SMTP.start(SMTP_SERVER, SMTP_PORT) do |smtp|
  
  begin
    #send email to each returned address
    contacts.flatten.each do |email|
      smtp.send_message get_email_message(email, host, evidence), EMAIL_FROM, email
      #log ip address and email 
      my_file = File.new(EMAIL_LOG_FILE, 'a+')
      my_file.puts "Report generated for #{host} on #{Time.now.to_s} and sent to #{email}"
    end
  ensure
    smtp.finish
  end

end
