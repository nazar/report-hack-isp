#! /usr/bin/ruby

require 'net/smtp'

#SMTP server
SMTP_SERVER = 'localhost'
SMTP_PORT   = 25

#EMAIL message setup
EMAIL_FROM    = ADD_YOUR_RETURN_EMAIL_HERE
EMAIL_SUBJECT = 'Security Alert - Your Server Has Been Hacked!'

#guess apps... override if required
GREP_BIN  = `which grep`.strip
CAT_BIN   = `which cat`.strip
WHOIS_BIN = `which whois`.strip

#LOG_FILE = SSHD's log file
LOG_FILE = '/var/log/sshd/current'

#misc
TIME_LOCALE = 'GMT'
EMAIL_LOG_FILE    = '/var/log/notify_isp.log'

#check that we have all our BINs
raise 'Could not find grep on your system. Manually configure GREP_BIN' if GREP_BIN == ''
raise 'Could not find cat on your system. Manually configure CAT_BIN' if CAT_BIN == ''
raise 'Could not find whois on your system. Manually configure WHOIS_BIN' if WHOIS_BIN == ''


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

  email_message = <<EOF
From: #{EMAIL_FROM}
To: #{to_address}
Subject: #{EMAIL_SUBJECT}
Date: #{time2str(Time.now)}

To whom it may concern.

We have detected a hack attempt originating from your network from ip: #{offender}

This suggests that the above server has been compromised and is a participant in a botnet.

This means that your server has been hacked and now, in turn, is attempting to hack other servers on the Internet.

This IP address has now been blacklisted to protect our service from further brute force attacks. Furthermore, this IP address has been uploaded to a centralised database. This means that this IP address will also shortly be blacklisted by any member who queries this central database.

An excerpt from our logfiles. All times shown are in #{TIME_LOCALE}:

#{evidence}

Regards.
Panther Software Admin

EOF

end

################# MAIN ##########################

#extract ip/domain from passed parameter
if ARGV.length > 0
  host = ARGV[0]
else
  raise 'No ip address or host given. Exiting'
end

#extract all email contacts from given host
contacts = []
lookup = eval("`#{WHOIS_BIN} #{host} | #{GREP_BIN} e-mail`")
lookup.each_line do |line|
  email = line[/([-a-z0-9]+[\w\.\-\+]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})/i]
  contacts << email unless email == nil
end

#extract evidence from ssh log file
evidence = eval("`#{CAT_BIN} #{LOG_FILE} | #{GREP_BIN} #{host}`")

Net::SMTP.start(SMTP_SERVER, SMTP_PORT) do |smtp|
  begin
    #send email to each returned address
    contacts.each do |email|
      smtp.send_message get_email_message(email, host, evidence), EMAIL_FROM, email
      #log ip address and email 
      my_file = File.new(EMAIL_LOG_FILE, 'a+')
      my_file.puts "Report generated for #{host} and sent to #{email}"
    end
  ensure
    smtp.finish
  end

end
