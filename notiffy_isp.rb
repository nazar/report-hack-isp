!# /usr/bin/ruby

require 'net/smtp'

#SMTP server
SMTP_SERVER = 'localhost'
SMTP_PORT   = 25
#EMAIL message setup
EMAIL_FROM    = 'admin@panthersoftware.com'
EMAIL_SUBJECT = 'Security Alert - Your Server Has Been Hacked!'
#guess apps... override if required
GREP_BIN  = `which grep`
CAT_BIN   = `which cat`
WHOIS_BIN = `which whois`

#LOG_FILE = SSHD's log file
LOG_FILE = '/var/log/pwdfail/current'

#misc
TIME_LOCALE = 'GMT'

#check that we have all our BINs
raise 'Could not find grep on your system. Manually configure GREP_BIN' if GREP_BIN.blank?
raise 'Could not find cat on your system. Manually configure CAT_BIN' if CAT_BIN.blank?
raise 'Could not find whois on your system. Manually configure WHOIS_BIN' if WHOIS_BIN.blank?

################# UTILS ########################
def time2str( tm )
  # [ruby-list:7928]
  gmt = Time.at(tm.to_i)
  gmt.gmtime
  offset = tm.to_i - Time.local(*gmt.to_a[0,6].reverse).to_i

  sprintf '%s, %s %s %d %02d:%02d:%02d %+.2d%.2d',
          WDAY[tm.wday], tm.mday, MONTH[tm.month],
          tm.year, tm.hour, tm.min, tm.sec,
          *(offset / 60).divmod(60)
end

def get_email_message(to_address)
  
email_message = <<EOF
From: #{EMAIL_FROM}
Reply
To: #{to_address}
Subject: #{EMAIL_SUBJECT}
Date: #{time2str(Time.now}

To whome it may concern.

We have detected a hack attempt which has originated from your network from ip: #{host}

This suggests that the above server has been comprimised and is a participant in a bot net.

This means that your server has been hack and now, in turn, is attempting to hack other servers on the Internet.

This IP address has now been blacklisted to prtected our service from further brute force attacks.
Furthermore, this IP address has been uploaded to a cetralised database. This means
that this IP address will also shortly be blacklisted by any member who queries this central database.

An excerpt from our logfiles. All times shown are in #{TIME_LOCALE}:

#{evidence}

Regards.
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
result = eval("`#{WHOIS_BIN #{host}} | #{GREP_BIN} e-mail`")
result.each_line do |line|
  email = line[/([-a-z0-9]+[\w\.\-\+]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})\z/i]
  contacts << email unless email.blank?
end

#extract evidence from ssh log file
evidence = eval("`#{CAT_BIN}` #{LOG_FILE} | #{GREP_BIN} #{host}")


Net::SMTP.start(SMTP_SERVER, SMTP_PORT) do |smtp|
  #send email to each returned address
  contacts.each do |email|
    puts get_email_message(email)
    # smtp.send_message get_email_message(email),
        #                   EMAIL_FROM,
        #                   email
        
  end
  
end
